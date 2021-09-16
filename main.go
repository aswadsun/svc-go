package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/spf13/cobra"
)

const version = "0.0.2"

func parseName(arn string) string {
	re := regexp.MustCompile(`(?:.+\/)(.+$)`)
	return re.FindStringSubmatch(arn)[1]
}

func getTaskDefFamily(taskdefarn string) string {
	re := regexp.MustCompile(`(^.+\/)(.+)(\:.+$)`)
	return re.FindStringSubmatch(taskdefarn)[2]
}

func setDesiredCount(svc *ecs.ECS, cluster string, service string, desiredCount int64) error {
	_, err := svc.UpdateService(
		&ecs.UpdateServiceInput{
			Cluster:      aws.String(cluster),
			Service:      aws.String(service),
			DesiredCount: aws.Int64(desiredCount),
		},
	)
	return err
}

func getMinCapacity(sess *session.Session, cluster string, service string) (int64, error) {
	svcAutoscaling := applicationautoscaling.New(sess)

	result, err := svcAutoscaling.DescribeScalableTargets(
		&applicationautoscaling.DescribeScalableTargetsInput{
			ServiceNamespace: aws.String("ecs"),
			ResourceIds: []*string{
				aws.String("service/" + cluster + "/" + service),
			},
		},
	)
	if err != nil {
		return 0, err
	}

	if len(result.ScalableTargets) == 0 {
		return 0, errors.New("Error: Cluster or Service not found")
	}

	return *result.ScalableTargets[0].MinCapacity, nil
}

func getServiceDescription(svc *ecs.ECS, cluster string, service string) (*ecs.DescribeServicesOutput, error) {
	result, err := svc.DescribeServices(
		&ecs.DescribeServicesInput{
			Cluster: aws.String(cluster),
			Services: []*string{
				aws.String(service),
			},
		},
	)
	if err != nil {
		return &ecs.DescribeServicesOutput{}, err
	}

	if len(result.Failures) > 0 {
		return &ecs.DescribeServicesOutput{}, errors.New("ServiceNotFoundException: Service not found")
	}

	return result, nil
}

func formatStringSlice(strSlice []string) string {
	retStr := "[ "

	length := len(strSlice)
	for index, val := range strSlice {
		retStr = retStr + fmt.Sprintf("\"%s\"", val)
		if index < length-1 {
			retStr = retStr + ", "
		}
	}

	return retStr + " ] "
}

func formatStringPointerSlice(strSlice []*string) string {
	retStr := "[ "

	length := len(strSlice)
	for index, val := range strSlice {
		retStr = retStr + fmt.Sprintf("\"%s\"", *val)
		if index < length-1 {
			retStr = retStr + ", "
		}
	}

	return retStr + " ] "
}

func getUserName(sess *session.Session) (string, error) {
	svc := iam.New(sess)
	result, err := svc.GetUser(&iam.GetUserInput{})
	if err != nil {
		return "", err
	}
	return *result.User.UserName, nil
}

func main() {

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := ecs.New(sess)

	var cmdList = &cobra.Command{
		Use:   "list [cluster_name]",
		Short: "List available ECS services in a cluster",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			result, err := svc.ListServices(
				&ecs.ListServicesInput{
					Cluster:    aws.String(args[0]),
					MaxResults: aws.Int64(100),
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println("Cluster:    " + args[0])

			nSvc := len(result.ServiceArns)
			fmt.Printf("Service(s): %d\n", nSvc)

			if nSvc > 0 {
				fmt.Println("---")

				for _, svc := range result.ServiceArns {
					fmt.Printf("  %s\n", parseName(*svc))
				}
			}
		},
	}

	var cmdListCluster = &cobra.Command{
		Use:   "list-clusters",
		Short: "List available ECS clusters",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			result, err := svc.ListClusters(
				&ecs.ListClustersInput{
					MaxResults: aws.Int64(100),
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			nClusters := len(result.ClusterArns)
			fmt.Printf("Clusters: %d\n", nClusters)

			if nClusters > 0 {
				fmt.Println("---")

				for _, cluster := range result.ClusterArns {
					fmt.Printf("  %s\n", parseName(*cluster))
				}
			}
		},
	}

	var cmdRestart = &cobra.Command{
		Use:   "restart [cluster_name] [service_name]",
		Short: "Restart ECS Service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Restart ECS Service")
			fmt.Println("Cluster: " + args[0])
			fmt.Println("Service: " + args[1])

			_, err := svc.UpdateService(
				&ecs.UpdateServiceInput{
					Cluster:            aws.String(args[0]),
					Service:            aws.String(args[1]),
					ForceNewDeployment: aws.Bool(true),
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Printf("Successfully submitted command to restart ECS service ...\n\n")
		},
	}

	var cmdStart = &cobra.Command{
		Use:   "start [cluster_name] [service_name]",
		Short: "Start ECS Service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Start ECS Service")
			fmt.Println("Cluster: " + args[0])
			fmt.Println("Service: " + args[1])

			minCapacity, err := getMinCapacity(sess, args[0], args[1])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println("---")
			fmt.Printf("MinCapacity = %d\n", minCapacity)

			errCount := setDesiredCount(svc, args[0], args[1], minCapacity)
			if errCount != nil {
				fmt.Println(errCount)
				os.Exit(1)
			}

			fmt.Printf("Successfully set service desiredCount to %d ...\n\n", minCapacity)
		},
	}

	var cmdStatus = &cobra.Command{
		Use:   "status [cluster_name] [service_name]",
		Short: "Show ECS Service status",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			resultSvc, errSvc := getServiceDescription(svc, args[0], args[1])
			if errSvc != nil {
				fmt.Println(errSvc)
				os.Exit(1)
			}

			taskDef := *resultSvc.Services[0].TaskDefinition

			// use TaskDefinition family instead of service name
			// to show all running tasks including manual run tasks
			result, err := svc.ListTasks(
				&ecs.ListTasksInput{
					Cluster:    aws.String(args[0]),
					MaxResults: aws.Int64(100),
					Family:     aws.String(getTaskDefFamily(taskDef)),
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println("ECS Service Status")
			fmt.Println("Cluster: " + args[0])
			fmt.Println("Service: " + args[1])

			nTask := len(result.TaskArns)
			fmt.Printf("Task(s): %d\n", nTask)

			if nTask > 0 {
				fmt.Println("---")

				resultTasks, errTask := svc.DescribeTasks(
					&ecs.DescribeTasksInput{
						Cluster: aws.String(args[0]),
						Tasks:   result.TaskArns,
					},
				)
				if errTask != nil {
					fmt.Println(errTask)
					os.Exit(1)
				}

				for _, task := range resultTasks.Tasks {
					fmt.Printf("- Task Id:        %s\n", parseName(*task.TaskArn))
					fmt.Printf("  TaskDefinition: %s\n", parseName(*task.TaskDefinitionArn))
					fmt.Printf("  StartedBy:      %s\n", *task.StartedBy)
					if *task.LastStatus == "RUNNING" {
						// only print StartedAt if state is running to prevent panic of nil time
						fmt.Printf("  StartedAt:      %v\n", *task.StartedAt)
					}
					fmt.Printf("  LastStatus:     %s\n", *task.LastStatus)

					for idx, ovr := range task.Overrides.ContainerOverrides {
						if len(ovr.Command) > 0 {
							if idx == 0 {
								fmt.Printf("  Overrides:\n")
							}
							fmt.Printf("  - Container Name: %s\n", *ovr.Name)
							fmt.Printf("    Command:        %s\n", formatStringPointerSlice(ovr.Command))
						}
					}
					fmt.Println()
				}
			}

		},
	}

	var cmdStop = &cobra.Command{
		Use:   "stop [cluster_name] [service_name]",
		Short: "Stop ECS Service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Stop ECS Service")
			fmt.Println("Cluster: " + args[0])
			fmt.Println("Service: " + args[1])
			fmt.Println("---")

			err := setDesiredCount(svc, args[0], args[1], 0)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Printf("Successfully set service desiredCount to 0 ...\n\n")
		},
	}

	var cmdInfo = &cobra.Command{
		Use:   "info [cluster_name] [service_name]",
		Short: "Show info of ECS Service",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			resultSvc, errSvc := getServiceDescription(svc, args[0], args[1])
			if errSvc != nil {
				fmt.Println(errSvc)
				os.Exit(1)
			}

			taskDef := *resultSvc.Services[0].TaskDefinition

			resultTask, errTask := svc.DescribeTaskDefinition(
				&ecs.DescribeTaskDefinitionInput{
					TaskDefinition: aws.String(taskDef),
				},
			)
			if errTask != nil {
				fmt.Println(errTask)
				os.Exit(1)
			}

			fmt.Println("ECS Service Info")
			fmt.Println("Cluster:         " + args[0])
			fmt.Println("Service:         " + args[1])
			fmt.Println("Task Definition: " + parseName(taskDef))

			nContainer := len(resultTask.TaskDefinition.ContainerDefinitions)
			fmt.Printf("Container(s):    %d\n", nContainer)

			if nContainer > 0 {
				fmt.Println("---")

				for _, container := range resultTask.TaskDefinition.ContainerDefinitions {
					fmt.Printf("- Container name: %s\n", *container.Name)
					fmt.Printf("  Image:          %s\n", *container.Image)

					if len(container.EntryPoint) > 0 {
						fmt.Println("  EntryPoint:     " + formatStringPointerSlice(container.EntryPoint))
					}

					if len(container.Command) > 0 {
						fmt.Println("  Command:        " + formatStringPointerSlice(container.Command))
					}

					fmt.Println()
				}
			}
		},
	}

	var cmdRunTask = &cobra.Command{
		Use:   "run-task [cluster_name] [service_name] [container_name] [commands...]",
		Short: "Manually run tasks of ECS Service with command override",
		Args:  cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {

			user, errUser := getUserName(sess)
			if errUser != nil {
				panic(errUser)
			}

			fmt.Println("Manually run tasks by " + user)
			fmt.Println("Cluster:   " + args[0])
			fmt.Println("Service:   " + args[1])
			fmt.Println("Container: " + args[2])
			fmt.Println("Command:   " + formatStringSlice(args[3:]))
			fmt.Println("---")

			resultSvc, errSvc := getServiceDescription(svc, args[0], args[1])
			if errSvc != nil {
				fmt.Println(errSvc)
				os.Exit(1)
			}

			var cmdList []*string
			for _, val := range args[3:] {
				val2 := val
				cmdList = append(cmdList, &val2)
			}

			contOverride := &ecs.ContainerOverride{
				Name:    aws.String(args[2]),
				Command: cmdList,
			}

			result, err := svc.RunTask(
				&ecs.RunTaskInput{
					Cluster:              aws.String(args[0]),
					LaunchType:           aws.String("FARGATE"),
					NetworkConfiguration: resultSvc.Services[0].NetworkConfiguration,
					StartedBy:            aws.String("manual/" + user),
					TaskDefinition:       resultSvc.Services[0].TaskDefinition,
					Overrides: &ecs.TaskOverride{
						ContainerOverrides: []*ecs.ContainerOverride{contOverride},
					},
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			if len(result.Failures) > 0 {
				fmt.Println(result.Failures)
				os.Exit(1)
			}

			fmt.Printf("Successfully submitted command to manually run task: %s\n\n", parseName(*result.Tasks[0].TaskArn))
		},
	}

	var cmdStopTask = &cobra.Command{
		Use:   "stop-task [cluster_name] [task_id]",
		Short: "Stop specific task of ECS Service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			user, errUser := getUserName(sess)
			if errUser != nil {
				panic(errUser)
			}

			result, err := svc.StopTask(
				&ecs.StopTaskInput{
					Cluster: aws.String(args[0]),
					Reason:  aws.String("Stopped by " + user),
					Task:    aws.String(args[1]),
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Printf("Successfully submitted command to stop ECS task: %s\n\n", parseName(*result.Task.TaskArn))
		},
	}

	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of svc",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}

	var rootCmd = &cobra.Command{
		Use:   "svc",
		Short: "ECS Service Utility v" + version,
	}
	rootCmd.AddCommand(cmdList, cmdListCluster, cmdRestart, cmdStart, cmdStatus, cmdStop, cmdInfo, cmdRunTask, cmdStopTask, cmdVersion)
	rootCmd.Execute()
}

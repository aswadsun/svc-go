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
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/cobra"
)

const version = "0.1.3"

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
	svc := sts.New(sess)
	result, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return parseName(*result.Arn), nil
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

			var services []*string

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

			services = append(services, result.ServiceArns...)

			for result.NextToken != nil {
				result, err = svc.ListServices(
					&ecs.ListServicesInput{
						NextToken:  result.NextToken,
						Cluster:    aws.String(args[0]),
						MaxResults: aws.Int64(100),
					},
				)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				services = append(services, result.ServiceArns...)
			}

			fmt.Println("Cluster:    " + args[0])

			nSvc := len(services)
			fmt.Printf("Service(s): %d\n", nSvc)

			if nSvc > 0 {
				fmt.Println("---")

				for _, svc := range services {
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
		Short: "Show information of ECS Service",
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

	var cmdListCrons = &cobra.Command{
		Use:   "list-crons [cluster_name]",
		Short: "List all crons (scheduled tasks) in ECS cluster",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

			resultCluster, errCluster := svc.DescribeClusters(
				&ecs.DescribeClustersInput{
					Clusters: []*string{
						aws.String(args[0]),
					},
				},
			)
			if errCluster != nil {
				fmt.Println(errCluster)
				os.Exit(1)
			}
			if len(resultCluster.Failures) > 0 {
				fmt.Println("Cluster not found")
				os.Exit(1)
			}

			eb := eventbridge.New(sess)

			var rules []*string

			result, err := eb.ListRuleNamesByTarget(
				&eventbridge.ListRuleNamesByTargetInput{
					TargetArn: resultCluster.Clusters[0].ClusterArn,
					Limit:     aws.Int64(100),
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			rules = append(rules, result.RuleNames...)

			for result.NextToken != nil {
				result, err = eb.ListRuleNamesByTarget(
					&eventbridge.ListRuleNamesByTargetInput{
						NextToken: result.NextToken,
						TargetArn: resultCluster.Clusters[0].ClusterArn,
						Limit:     aws.Int64(100),
					},
				)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				rules = append(rules, result.RuleNames...)
			}

			fmt.Println("Cluster:               " + args[0])
			fmt.Printf("Crons/Scheduled Tasks: %d\n", len(rules))
			fmt.Println("---")

			for _, rule := range rules {
				fmt.Printf("  %s\n", *rule)
			}
		},
	}

	var cmdInfoCron = &cobra.Command{
		Use:   "info-cron [cron_name]",
		Short: "Show information of specified cron",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			eb := eventbridge.New(sess)

			result, err := eb.DescribeRule(
				&eventbridge.DescribeRuleInput{
					Name: aws.String(args[0]),
				},
			)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println("Cron/Scheduled Task")
			if result.ScheduleExpression != nil {
				fmt.Printf("Name:               %s\n", *result.Name)
				fmt.Printf("Event Bus:          %s\n", *result.EventBusName)
				fmt.Printf("State:              %s\n", *result.State)
				fmt.Printf("ScheduleExpression: %s\n", *result.ScheduleExpression)
			}
			if result.EventPattern != nil {
				fmt.Printf("Name:         %s\n", *result.Name)
				fmt.Printf("Event Bus:    %s\n", *result.EventBusName)
				fmt.Printf("State:        %s\n", *result.State)
				fmt.Printf("EventPattern: %s\n", *result.EventPattern)
			}

			resultTarget, errTarget := eb.ListTargetsByRule(
				&eventbridge.ListTargetsByRuleInput{
					EventBusName: result.EventBusName,
					Limit:        aws.Int64(100),
					Rule:         result.Name,
				},
			)
			if errTarget != nil {
				fmt.Println(errTarget)
				os.Exit(1)
			}
			fmt.Printf("Target(s):\n")
			fmt.Printf("---\n")
			for _, target := range resultTarget.Targets {
				if target.EcsParameters != nil {
					fmt.Printf("- Id:              %s\n", *target.Id)
					fmt.Printf("  ARN:             %s\n", *target.Arn)
					fmt.Printf("  Task Definition: %s\n", parseName(*target.EcsParameters.TaskDefinitionArn))
				} else {
					fmt.Printf("- Id:  %s\n", *target.Id)
					fmt.Printf("  ARN: %s\n", *target.Arn)
				}
				fmt.Println()
			}
		},
	}

	var cmdSetCron = &cobra.Command{
		Use:   "set-cron [cron_name]",
		Short: "Set cron enable/disable or update the schedule expression",
		Long: `Set cron enable/disable or update the schedule expression
Examples:
   svc set-cron cron_name --enable
   svc set-cron cron_name --disable
   svc set-cron cron_name --schedule "rate(15 minutes)"
   svc set-cron cron_name --schedule "cron(0 1 * * ? *)"
   svc set-cron cron_name --enable --schedule "cron(0 2 * * ? *)"
   svc set-cron cron_name --disable --schedule "cron(0 3 * * ? *)"

Reference:
   https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			schedule, _ := cmd.Flags().GetString("schedule")
			enable, _ := cmd.Flags().GetBool("enable")
			disable, _ := cmd.Flags().GetBool("disable")

			if schedule == "" && !enable && !disable {
				cmd.Help()
			} else if enable && disable {
				fmt.Println("Cannot --enable and --disable at the same time")
				fmt.Println()
			} else {

				eb := eventbridge.New(sess)

				result, err := eb.DescribeRule(
					&eventbridge.DescribeRuleInput{
						Name: aws.String(args[0]),
					},
				)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				if enable {

					if *result.State == "ENABLED" {
						fmt.Printf("Cron/Scheduled Task: %s is already in ENABLED state!\n", *result.Name)
					} else {
						_, errEnable := eb.EnableRule(
							&eventbridge.EnableRuleInput{
								EventBusName: result.EventBusName,
								Name:         result.Name,
							},
						)
						if errEnable != nil {
							fmt.Println(errEnable)
							os.Exit(1)
						}
						fmt.Printf("Successfully ENABLED %s...\n", *result.Name)
						*result.State = "ENABLED"
					}

				} else if disable {

					if *result.State == "DISABLED" {
						fmt.Printf("Cron/Scheduled Task: %s is already in DISABLED state!\n", *result.Name)
					} else {
						_, errDisable := eb.DisableRule(
							&eventbridge.DisableRuleInput{
								EventBusName: result.EventBusName,
								Name:         result.Name,
							},
						)
						if errDisable != nil {
							fmt.Println(errDisable)
							os.Exit(1)
						}
						fmt.Printf("Successfully DISABLED %s...\n", *result.Name)
						*result.State = "DISABLED"
					}

				}

				if schedule != "" {
					if result.EventPattern != nil {
						fmt.Println("Cannot set schedule expression of cron/scheduled task with EventPattern!")
						fmt.Println()
					} else {
						if schedule == *result.ScheduleExpression {
							fmt.Printf("ScheduleExpression of cron/scheduled task: %s, is already \"%s\", no need to update!\n", *result.Name, *result.ScheduleExpression)
						} else {
							_, errRule := eb.PutRule(
								&eventbridge.PutRuleInput{
									Name:               result.Name,
									Description:        result.Description,
									EventBusName:       result.EventBusName,
									State:              result.State,
									RoleArn:            result.RoleArn,
									ScheduleExpression: aws.String(schedule),
								},
							)
							if errRule != nil {
								fmt.Println(errRule)
								os.Exit(1)
							}
							fmt.Printf("Successfully set schedule expression of cron/scheduled task: %s, to \"%s\"...\n", *result.Name, schedule)
						}
						if *result.State == "DISABLED" {
							fmt.Println("Warning, the cron/scheduled task state is DISABLED! It will not run on specified schedule unless it is ENABLED.")
						}
					}
				}

				fmt.Println()
			}

		},
	}

	var cmdRunCron = &cobra.Command{
		Use:   "run-cron [cron_name]",
		Short: "Run ECS task(s) using task definition from cron/scheduled task target(s)",
		Long: `Run ECS task(s) using task definition from cron/scheduled task target(s).
Only run ECS target with valid task definition. Other target such as Lambda function will not be invoked.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			eb := eventbridge.New(sess)

			resultRule, errRule := eb.DescribeRule(
				&eventbridge.DescribeRuleInput{
					Name: aws.String(args[0]),
				},
			)
			if errRule != nil {
				fmt.Println(errRule)
				os.Exit(1)
			}

			fmt.Printf("Run ECS task(s) using task definition from cron/scheduled task target(s)\n")
			fmt.Printf("Cron/Scheduled Task Name: %s\n", *resultRule.Name)

			resultTarget, errTarget := eb.ListTargetsByRule(
				&eventbridge.ListTargetsByRuleInput{
					EventBusName: resultRule.EventBusName,
					Limit:        aws.Int64(100),
					Rule:         resultRule.Name,
				},
			)
			if errTarget != nil {
				fmt.Println(errTarget)
				os.Exit(1)
			}

			fmt.Printf("---\n")

			user, errUser := getUserName(sess)
			if errUser != nil {
				panic(errUser)
			}

			var result *ecs.RunTaskOutput
			var err error
			var netCfg *ecs.NetworkConfiguration

			for _, target := range resultTarget.Targets {
				if target.EcsParameters != nil {
					fmt.Printf("- Cluster:         %s\n", parseName(*target.Arn))
					fmt.Printf("  Task Definition: %s\n", parseName(*target.EcsParameters.TaskDefinitionArn))

					netCfg = &ecs.NetworkConfiguration{
						AwsvpcConfiguration: &ecs.AwsVpcConfiguration{
							AssignPublicIp: target.EcsParameters.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp,
							SecurityGroups: target.EcsParameters.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups,
							Subnets:        target.EcsParameters.NetworkConfiguration.AwsvpcConfiguration.Subnets,
						},
					}

					result, err = svc.RunTask(
						&ecs.RunTaskInput{
							Cluster:              target.Arn,
							LaunchType:           target.EcsParameters.LaunchType,
							NetworkConfiguration: netCfg,
							StartedBy:            aws.String("manual/" + user),
							TaskDefinition:       target.EcsParameters.TaskDefinitionArn,
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

					fmt.Printf("  Successfully submitted command to manually run task: %s\n\n", parseName(*result.Tasks[0].TaskArn))

				}
			}
		},
	}

	var cmdStatusCron = &cobra.Command{
		Use:   "status-cron [cron_name]",
		Short: "Show status of tasks which run by cron/scheduled task",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			eb := eventbridge.New(sess)

			resultRule, errRule := eb.DescribeRule(
				&eventbridge.DescribeRuleInput{
					Name: aws.String(args[0]),
				},
			)
			if errRule != nil {
				fmt.Println(errRule)
				os.Exit(1)
			}

			fmt.Printf("Cron/Scheduled Task Name: %s\n", *resultRule.Name)

			resultTarget, errTarget := eb.ListTargetsByRule(
				&eventbridge.ListTargetsByRuleInput{
					EventBusName: resultRule.EventBusName,
					Limit:        aws.Int64(100),
					Rule:         resultRule.Name,
				},
			)
			if errTarget != nil {
				fmt.Println(errTarget)
				os.Exit(1)
			}

			fmt.Printf("---\n")

			for _, target := range resultTarget.Targets {
				if target.EcsParameters != nil {

					result, err := svc.ListTasks(
						&ecs.ListTasksInput{
							Cluster:    target.Arn,
							MaxResults: aws.Int64(100),
							Family:     aws.String(getTaskDefFamily(*target.EcsParameters.TaskDefinitionArn)),
						},
					)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					fmt.Printf("- Cluster:         %s\n", parseName(*target.Arn))
					fmt.Printf("  Task Definition: %s\n", parseName(*target.EcsParameters.TaskDefinitionArn))

					nTask := len(result.TaskArns)
					fmt.Printf("  Task(s): %d\n", nTask)

					if nTask > 0 {
						fmt.Println("  ---")

						resultTasks, errTask := svc.DescribeTasks(
							&ecs.DescribeTasksInput{
								Cluster: target.Arn,
								Tasks:   result.TaskArns,
							},
						)
						if errTask != nil {
							fmt.Println(errTask)
							os.Exit(1)
						}

						for _, task := range resultTasks.Tasks {
							fmt.Printf("  - Task Id:        %s\n", parseName(*task.TaskArn))
							fmt.Printf("    TaskDefinition: %s\n", parseName(*task.TaskDefinitionArn))
							fmt.Printf("    StartedBy:      %s\n", *task.StartedBy)
							if *task.LastStatus == "RUNNING" {
								// only print StartedAt if state is running to prevent panic of nil time
								fmt.Printf("    StartedAt:      %v\n", *task.StartedAt)
							}
							fmt.Printf("    LastStatus:     %s\n", *task.LastStatus)

							for idx, ovr := range task.Overrides.ContainerOverrides {
								if len(ovr.Command) > 0 {
									if idx == 0 {
										fmt.Printf("    Overrides:\n")
									}
									fmt.Printf("    - Container Name: %s\n", *ovr.Name)
									fmt.Printf("      Command:        %s\n", formatStringPointerSlice(ovr.Command))
								}
							}
							fmt.Println()
						}
					}

				}
			}
		},
	}

	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}

	var rootCmd = &cobra.Command{
		Use:     "svc",
		Version: version,
		Short:   "ECS Service Utility v" + version,
	}

	rootCmd.AddCommand(cmdList, cmdListCluster, cmdRestart, cmdStart, cmdStatus, cmdStop, cmdInfo, cmdVersion)
	rootCmd.AddCommand(cmdRunTask, cmdStopTask, cmdListCrons, cmdInfoCron, cmdSetCron, cmdRunCron, cmdStatusCron)
	cmdSetCron.Flags().BoolP("enable", "e", false, "Enable cron")
	cmdSetCron.Flags().BoolP("disable", "d", false, "Disable cron")
	cmdSetCron.Flags().StringP("schedule", "s", "", "Cron Schedule Expression")
	rootCmd.Execute()
}

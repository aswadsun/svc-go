package main

import (
	"fmt"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/spf13/cobra"
)

const version = "0.0.1"

func parseName(arn string) string {
	re := regexp.MustCompile(`(?:.+\/)(.+$)`)
	return re.FindStringSubmatch(arn)[1]
}

func setDesiredCount(sess *session.Session, cluster string, service string, desiredCount int64) error {
	svc := ecs.New(sess)
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

	return *result.ScalableTargets[0].MinCapacity, nil

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

			fmt.Println("Cluster: " + args[0])

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

			fmt.Printf("Number of Services: %d\n", len(result.ServiceArns))
			fmt.Println("---")

			for _, svc := range result.ServiceArns {
				fmt.Printf("  %s\n", parseName(*svc))
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

			fmt.Printf("List of Clusters: %d\n", len(result.ClusterArns))
			fmt.Println("---")

			for _, cluster := range result.ClusterArns {
				fmt.Printf("  %s\n", parseName(*cluster))
			}

		},
	}

	var cmdStart = &cobra.Command{
		Use:   "start [cluster_name] [service name]",
		Short: "Start ECS Service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			fmt.Println("Cluster: " + args[0])
			fmt.Println("Service: " + args[1])
			fmt.Println("---")

			minCapacity, err := getMinCapacity(sess, args[0], args[1])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Printf("MinCapacity = %d\n", minCapacity)

			err1 := setDesiredCount(sess, args[0], args[1], minCapacity)
			if err1 != nil {
				fmt.Println(err1)
				os.Exit(1)
			}

			fmt.Printf("Successfully set service desiredCount to %d ...\n", minCapacity)
		},
	}

	var cmdStatus = &cobra.Command{
		Use:   "status [cluster_name] [service name]",
		Short: "Show ECS Service status",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			fmt.Println("Cluster: " + args[0])
			fmt.Println("Service: " + args[1])

			result, err := svc.ListTasks(
				&ecs.ListTasksInput{
					Cluster:     aws.String(args[0]),
					MaxResults:  aws.Int64(100),
					ServiceName: aws.String(args[1]),
				},
			)

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Printf("Number of Running Tasks: %d\n", len(result.TaskArns))
			fmt.Println("---")

			for _, svc := range result.TaskArns {
				fmt.Printf("  %s\n", *svc)
			}

		},
	}

	var cmdStop = &cobra.Command{
		Use:   "stop [cluster_name] [service name]",
		Short: "Stop ECS Service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			fmt.Println("Cluster: " + args[0])
			fmt.Println("Service: " + args[1])

			err := setDesiredCount(sess, args[0], args[1], 0)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println("Successfully set service desiredCount to 0 ...")
		},
	}

	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of svc",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("ECS Service Utility v" + version)
		},
	}

	var rootCmd = &cobra.Command{
		Use:   "svc",
		Short: "ECS Service Utility",
	}
	rootCmd.AddCommand(cmdList, cmdListCluster, cmdStart, cmdStatus, cmdStop, cmdVersion)
	rootCmd.Execute()
}

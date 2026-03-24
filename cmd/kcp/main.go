// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcaplay binary load an offline capture (pcap file) and replay
// it on the select interface, with an emphasis on packet timing
package main

import (
	"log"

	"github.com/spf13/cobra"
)

func main() {

	kcp := New()
	var rootCmd = &cobra.Command{
		Use:   "kcp",
		Short: "kcp",
		Long:  `.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if kcp.GetPcapFileName() == "" {
				return cmd.Help()
			}
			return kcp.Run()
		},
	}

	// 解析配置参数
	kcp.ParseFlags(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		return
	}
}

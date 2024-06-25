package org.json;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;


public class Main {
    static String serviceName="sa-tools-changeset-service";

    public static void main(String[] args) {
        String grypeOutpuString = runGrypeCommand();
        List<Vulnerability> vulnerabilities = parseGrypeOutput(grypeOutpuString);  
        System.out.println("looking for vulnerabilities");
        displayVulnerablities(vulnerabilities);
        getPackageforDependencyTree(vulnerabilities);
    }

    public static String runGrypeCommand(){
        StringBuilder output = new StringBuilder();
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", "cd ~/Repos/"+serviceName +" && grype . --scope all-layers --only-fixed --by-cve -o json");
        try{
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while((line = reader.readLine()) != null){
                output.append(line);
            }

            int exitCode=process.waitFor();
            if(exitCode !=0){
                throw new RuntimeException("Error executing Grype command"+ exitCode);
            }

        }catch(IOException | InterruptedException e){
            e.printStackTrace();
        }   
        return output.toString();
    }


    private static List<Vulnerability> parseGrypeOutput(String grypeOutput){
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        try{
            JSONObject jsonObject = new JSONObject(grypeOutput);
            JSONArray matches = jsonObject.getJSONArray("matches");

            for(int i=0; i<matches.length(); i++){
                JSONObject match = matches.getJSONObject(i);
                JSONObject vulnerability = match.getJSONObject("vulnerability");
                String id = vulnerability.getString("id");
                String description = vulnerability.getString("description");
                String severity = vulnerability.getString("severity");

                JSONObject artifact = match.getJSONObject("artifact");
                String name = artifact.getString("name");
                JSONObject metadata = artifact.getJSONObject("metadata");
                String pomArtifactID = metadata.getString("pomArtifactID");
                String pomGroupID = metadata.getString("pomGroupID");
                vulnerabilities.add(new Vulnerability(id, description, severity ,name, pomArtifactID, pomGroupID));
            }
        }catch(Exception e){
            e.printStackTrace();
        }
        return vulnerabilities;
    }

    private static void displayVulnerablities(List<Vulnerability> vulnerabilities){
        if (!vulnerabilities.isEmpty()) 
        {
            for(Vulnerability vulnerability: vulnerabilities)
            {
                if(vulnerability.getName()== null || vulnerability.getName() == ""){
                    System.out.println("No vulnerabilities found in" );
                }
                else
                {
                    System.out.println("Vulnerabilities found:");
                    System.out.println("Name : "+vulnerability.getName());
                    System.out.println("ID : "+vulnerability.getId());
                    System.out.println("Description : "+vulnerability.getDescription());
                    System.out.println("Severity : "+vulnerability.getSeverity());
                    System.out.println("--------------------------------------------------------------------------------");
                }
            }
       }
       else
        {
            System.out.println("No vulnerabilities found in " + serviceName);
        }
    }

    private static void getPackageforDependencyTree(List<Vulnerability> vulnerabilities)
    {
        for(Vulnerability vulnerability: vulnerabilities)
        {
            System.out.println("Fetching Dependency tree for: "+vulnerability.getName());
            runMavenCommand(vulnerability);
        }
    }

    private static void runMavenCommand(Vulnerability vulnerability)
    {
        StringBuilder output = new StringBuilder();
        ProcessBuilder processBuilder = new ProcessBuilder();
        try
        {
            processBuilder.command("bash", "-c", "cd ~/Repos/"+serviceName +" &&  mvn dependency:tree -Dincludes="+vulnerability.getPackageName());
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while((line = reader.readLine()) != null)
            {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            if(exitCode !=0)
            {
                throw new RuntimeException("Maven Command failed" + exitCode);
            }
            System.out.println(output.toString());
        }
        catch(IOException | InterruptedException e){
            e.printStackTrace();
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
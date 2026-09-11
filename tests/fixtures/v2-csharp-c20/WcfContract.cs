using System.ServiceModel;

[ServiceContract]
public interface ICommandService
{
    [OperationContract]
    string Execute(string command);
}

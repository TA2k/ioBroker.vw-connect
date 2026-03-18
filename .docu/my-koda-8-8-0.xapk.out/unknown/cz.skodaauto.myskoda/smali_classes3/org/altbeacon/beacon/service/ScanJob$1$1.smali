.class Lorg/altbeacon/beacon/service/ScanJob$1$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/service/ScanJob$1;->run()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$1:Lorg/altbeacon/beacon/service/ScanJob$1;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/ScanJob$1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanJob$1$1;->this$1:Lorg/altbeacon/beacon/service/ScanJob$1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "Scan job runtime expired: "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob$1$1;->this$1:Lorg/altbeacon/beacon/service/ScanJob$1;

    .line 13
    .line 14
    iget-object v2, v2, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const/4 v2, 0x0

    .line 24
    new-array v3, v2, [Ljava/lang/Object;

    .line 25
    .line 26
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1$1;->this$1:Lorg/altbeacon/beacon/service/ScanJob$1;

    .line 30
    .line 31
    iget-object v0, v0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 32
    .line 33
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->j(Lorg/altbeacon/beacon/service/ScanJob;)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1$1;->this$1:Lorg/altbeacon/beacon/service/ScanJob$1;

    .line 37
    .line 38
    iget-object v0, v0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 39
    .line 40
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->c(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanState;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->save()V

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1$1;->this$1:Lorg/altbeacon/beacon/service/ScanJob$1;

    .line 48
    .line 49
    iget-object v1, v0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 50
    .line 51
    iget-object v0, v0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 52
    .line 53
    invoke-virtual {v1, v0, v2}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1$1;->this$1:Lorg/altbeacon/beacon/service/ScanJob$1;

    .line 57
    .line 58
    iget-object v0, v0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 59
    .line 60
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->e(Lorg/altbeacon/beacon/service/ScanJob;)Landroid/os/Handler;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    new-instance v1, Lorg/altbeacon/beacon/service/ScanJob$1$1$1;

    .line 65
    .line 66
    invoke-direct {v1, p0}, Lorg/altbeacon/beacon/service/ScanJob$1$1$1;-><init>(Lorg/altbeacon/beacon/service/ScanJob$1$1;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 70
    .line 71
    .line 72
    return-void
.end method

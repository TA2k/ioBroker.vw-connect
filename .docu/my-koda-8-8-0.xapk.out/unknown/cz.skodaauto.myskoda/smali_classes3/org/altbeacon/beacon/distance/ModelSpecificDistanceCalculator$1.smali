.class Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/distance/ModelSpecificDistanceUpdater$CompletionHandler;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->requestModelMapFromWeb()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onComplete(Ljava/lang/String;Ljava/lang/Exception;I)V
    .locals 1

    .line 1
    const-string v0, "ModelSpecificDistanceCalculator"

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 6
    .line 7
    invoke-static {p0}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->a(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    filled-new-array {p2, p0}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string p1, "Cannot updated distance models from online database at %s"

    .line 16
    .line 17
    invoke-static {v0, p1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    const/16 p2, 0xc8

    .line 22
    .line 23
    if-eq p3, p2, :cond_1

    .line 24
    .line 25
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 26
    .line 27
    invoke-static {p0}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->a(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    filled-new-array {p0, p1}, [Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string p1, "Cannot updated distance models from online database at %s due to HTTP status code %s"

    .line 40
    .line 41
    invoke-static {v0, p1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_1
    iget-object p2, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 46
    .line 47
    invoke-static {p2}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->a(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p2

    .line 51
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    const-string p3, "Successfully downloaded distance models from online database at %s"

    .line 56
    .line 57
    invoke-static {v0, p3, p2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const/4 p2, 0x0

    .line 61
    :try_start_0
    iget-object p3, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 62
    .line 63
    invoke-virtual {p3, p1}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->buildModelMapWithLock(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-object p3, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 67
    .line 68
    invoke-static {p3, p1}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->e(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;Ljava/lang/String;)Z

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-eqz p1, :cond_2

    .line 73
    .line 74
    iget-object p1, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 75
    .line 76
    invoke-static {p1}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->d(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;)V

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator$1;->this$0:Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;

    .line 80
    .line 81
    invoke-static {p0}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->b(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;)Lorg/altbeacon/beacon/distance/AndroidModel;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->findCalculatorForModelWithLock(Lorg/altbeacon/beacon/distance/AndroidModel;)Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    invoke-static {p0, p1}, Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;->c(Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculator;Lorg/altbeacon/beacon/distance/DistanceCalculator;)V

    .line 90
    .line 91
    .line 92
    const-string p0, "Successfully updated distance model with latest from online database"

    .line 93
    .line 94
    new-array p1, p2, [Ljava/lang/Object;

    .line 95
    .line 96
    invoke-static {v0, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :catch_0
    move-exception p0

    .line 101
    goto :goto_0

    .line 102
    :cond_2
    return-void

    .line 103
    :goto_0
    const-string p1, "Cannot parse json from downloaded distance model"

    .line 104
    .line 105
    new-array p2, p2, [Ljava/lang/Object;

    .line 106
    .line 107
    invoke-static {p0, v0, p1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    return-void
.end method

.class public final Lac0/o;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Z

.field public e:Z

.field public f:Ldc0/e;

.field public g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

.field public h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

.field public i:Ljava/lang/Object;

.field public j:[Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

.field public k:Ljava/lang/Object;

.field public l:Ljava/lang/String;

.field public m:I

.field public n:I

.field public synthetic o:Ljava/lang/Object;

.field public final synthetic p:Lac0/w;

.field public q:I


# direct methods
.method public constructor <init>(Lac0/w;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lac0/o;->p:Lac0/w;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Lac0/o;->o:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lac0/o;->q:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lac0/o;->q:I

    .line 9
    .line 10
    iget-object p1, p0, Lac0/o;->p:Lac0/w;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p1, v0, p0}, Lac0/w;->d(ZLrx0/c;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.class public final Li70/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/IllegalArgumentException;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/IllegalArgumentException;I)V
    .locals 0

    .line 1
    iput p3, p0, Li70/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li70/g;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Li70/g;->f:Ljava/lang/IllegalArgumentException;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Li70/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li70/g;->f:Ljava/lang/IllegalArgumentException;

    .line 7
    .line 8
    invoke-static {v0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "Unable to get TripStatisticsIntervalType for the value "

    .line 13
    .line 14
    const-string v2, "\n"

    .line 15
    .line 16
    iget-object p0, p0, Li70/g;->e:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v1, p0, v2, v0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object v0, p0, Li70/g;->f:Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    invoke-static {v0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v1, "Unable to get TripStatisticsDataType for the value "

    .line 30
    .line 31
    const-string v2, "\n"

    .line 32
    .line 33
    iget-object p0, p0, Li70/g;->e:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, p0, v2, v0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    iget-object v0, p0, Li70/g;->f:Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    invoke-static {v0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const-string v1, "\n"

    .line 47
    .line 48
    const-string v2, " "

    .line 49
    .line 50
    const-string v3, "Unable to get TripStatisticsDataType for the value "

    .line 51
    .line 52
    iget-object p0, p0, Li70/g;->e:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {v3, p0, v1, v0, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

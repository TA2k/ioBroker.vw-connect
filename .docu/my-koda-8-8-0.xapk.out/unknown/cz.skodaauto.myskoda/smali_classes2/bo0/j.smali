.class public final synthetic Lbo0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J


# direct methods
.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    iput p3, p0, Lbo0/j;->d:I

    .line 2
    .line 3
    iput-wide p1, p0, Lbo0/j;->e:J

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lbo0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lbo0/j;->e:J

    .line 7
    .line 8
    invoke-static {v0, v1}, Lmy0/c;->o(J)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "add Nearby Pois to cache takes: "

    .line 13
    .line 14
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-wide v0, p0, Lbo0/j;->e:J

    .line 20
    .line 21
    invoke-static {v0, v1}, Lmy0/c;->o(J)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v0, "add offers to cache takes: "

    .line 26
    .line 27
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    iget-wide v0, p0, Lbo0/j;->e:J

    .line 33
    .line 34
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    sub-long/2addr v2, v0

    .line 39
    const-string p0, "startRPA(): RPA start took "

    .line 40
    .line 41
    const-string v0, "ms to start."

    .line 42
    .line 43
    invoke-static {v2, v3, p0, v0}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_2
    iget-wide v0, p0, Lbo0/j;->e:J

    .line 49
    .line 50
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 51
    .line 52
    .line 53
    move-result-wide v2

    .line 54
    sub-long/2addr v2, v0

    .line 55
    const-string p0, "startRPA(): RPA start took "

    .line 56
    .line 57
    const-string v0, "ms to start."

    .line 58
    .line 59
    invoke-static {v2, v3, p0, v0}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_3
    new-instance v0, Llj0/a;

    .line 65
    .line 66
    const-string v1, "climate_plans_detail_plan_"

    .line 67
    .line 68
    const-string v2, "_title"

    .line 69
    .line 70
    iget-wide v3, p0, Lbo0/j;->e:J

    .line 71
    .line 72
    invoke-static {v3, v4, v1, v2}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return-object v0

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

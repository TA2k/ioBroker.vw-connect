.class public final Lh0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/m1;


# instance fields
.field public final synthetic b:I

.field public final c:Lb0/m1;


# direct methods
.method public constructor <init>(JI)V
    .locals 1

    .line 1
    iput p3, p0, Lh0/g0;->b:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance p3, Lh0/g0;

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    invoke-direct {p3, p1, p2, v0}, Lh0/g0;-><init>(JI)V

    .line 13
    .line 14
    .line 15
    iput-object p3, p0, Lh0/g0;->c:Lb0/m1;

    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    new-instance p3, Lh0/k2;

    .line 22
    .line 23
    new-instance v0, Lh0/f0;

    .line 24
    .line 25
    invoke-direct {v0, p1, p2}, Lh0/f0;-><init>(J)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p3, p1, p2, v0}, Lh0/k2;-><init>(JLb0/m1;)V

    .line 29
    .line 30
    .line 31
    iput-object p3, p0, Lh0/g0;->c:Lb0/m1;

    .line 32
    .line 33
    return-void

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a()J
    .locals 2

    .line 1
    iget v0, p0, Lh0/g0;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh0/g0;->c:Lb0/m1;

    .line 7
    .line 8
    check-cast p0, Lh0/k2;

    .line 9
    .line 10
    iget-wide v0, p0, Lh0/k2;->b:J

    .line 11
    .line 12
    return-wide v0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lh0/g0;->c:Lb0/m1;

    .line 14
    .line 15
    check-cast p0, Lh0/g0;

    .line 16
    .line 17
    iget-object p0, p0, Lh0/g0;->c:Lb0/m1;

    .line 18
    .line 19
    check-cast p0, Lh0/k2;

    .line 20
    .line 21
    iget-wide v0, p0, Lh0/k2;->b:J

    .line 22
    .line 23
    return-wide v0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Lcom/google/crypto/tink/shaded/protobuf/d;)Lb0/l1;
    .locals 1

    .line 1
    iget v0, p0, Lh0/g0;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh0/g0;->c:Lb0/m1;

    .line 7
    .line 8
    check-cast p0, Lh0/k2;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lh0/k2;->b(Lcom/google/crypto/tink/shaded/protobuf/d;)Lb0/l1;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lh0/g0;->c:Lb0/m1;

    .line 16
    .line 17
    check-cast p0, Lh0/g0;

    .line 18
    .line 19
    iget-object p0, p0, Lh0/g0;->c:Lb0/m1;

    .line 20
    .line 21
    check-cast p0, Lh0/k2;

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lh0/k2;->b(Lcom/google/crypto/tink/shaded/protobuf/d;)Lb0/l1;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    iget-boolean p0, p0, Lb0/l1;->b:Z

    .line 28
    .line 29
    if-nez p0, :cond_1

    .line 30
    .line 31
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Ljava/lang/Throwable;

    .line 34
    .line 35
    instance-of p1, p0, Lh0/m0;

    .line 36
    .line 37
    if-eqz p1, :cond_0

    .line 38
    .line 39
    const-string p1, "CameraX"

    .line 40
    .line 41
    const-string v0, "The device might underreport the amount of the cameras. Finish the initialize task since we are already reaching the maximum number of retries."

    .line 42
    .line 43
    invoke-static {p1, v0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    check-cast p0, Lh0/m0;

    .line 47
    .line 48
    iget p0, p0, Lh0/m0;->d:I

    .line 49
    .line 50
    if-lez p0, :cond_0

    .line 51
    .line 52
    sget-object p0, Lb0/l1;->f:Lb0/l1;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    sget-object p0, Lb0/l1;->d:Lb0/l1;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    sget-object p0, Lb0/l1;->e:Lb0/l1;

    .line 59
    .line 60
    :goto_0
    return-object p0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

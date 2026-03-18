.class public final Luz0/t0;
.super Luz0/m0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final e:Lsz0/h;


# direct methods
.method public constructor <init>(Lqz0/a;Lqz0/a;I)V
    .locals 3

    .line 1
    iput p3, p0, Luz0/t0;->d:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p3, "keySerializer"

    .line 7
    .line 8
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p3, "valueSerializer"

    .line 12
    .line 13
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, p1, p2}, Luz0/m0;-><init>(Lqz0/a;Lqz0/a;)V

    .line 17
    .line 18
    .line 19
    sget-object p3, Lsz0/k;->d:Lsz0/k;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    new-array v0, v0, [Lsz0/g;

    .line 23
    .line 24
    new-instance v1, Luz0/r0;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {v1, p1, p2, v2}, Luz0/r0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 28
    .line 29
    .line 30
    const-string p1, "kotlin.collections.Map.Entry"

    .line 31
    .line 32
    invoke-static {p1, p3, v0, v1}, Lkp/x8;->d(Ljava/lang/String;Lkp/y8;[Lsz0/g;Lay0/k;)Lsz0/h;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Luz0/t0;->e:Lsz0/h;

    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_0
    const-string p3, "keySerializer"

    .line 40
    .line 41
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const-string p3, "valueSerializer"

    .line 45
    .line 46
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-direct {p0, p1, p2}, Luz0/m0;-><init>(Lqz0/a;Lqz0/a;)V

    .line 50
    .line 51
    .line 52
    const/4 p3, 0x0

    .line 53
    new-array p3, p3, [Lsz0/g;

    .line 54
    .line 55
    new-instance v0, Luz0/r0;

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    invoke-direct {v0, p1, p2, v1}, Luz0/r0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 59
    .line 60
    .line 61
    const-string p1, "kotlin.Pair"

    .line 62
    .line 63
    invoke-static {p1, p3, v0}, Lkp/x8;->c(Ljava/lang/String;[Lsz0/g;Lay0/k;)Lsz0/h;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    iput-object p1, p0, Luz0/t0;->e:Lsz0/h;

    .line 68
    .line 69
    return-void

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Luz0/t0;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/l;

    .line 7
    .line 8
    const-string p0, "<this>"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    check-cast p1, Ljava/util/Map$Entry;

    .line 17
    .line 18
    const-string p0, "<this>"

    .line 19
    .line 20
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Luz0/t0;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/l;

    .line 7
    .line 8
    const-string p0, "<this>"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    check-cast p1, Ljava/util/Map$Entry;

    .line 17
    .line 18
    const-string p0, "<this>"

    .line 19
    .line 20
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Luz0/t0;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Llx0/l;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_0
    new-instance p0, Luz0/s0;

    .line 13
    .line 14
    invoke-direct {p0, p1, p2}, Luz0/s0;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 1

    .line 1
    iget v0, p0, Luz0/t0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Luz0/t0;->e:Lsz0/h;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Luz0/t0;->e:Lsz0/h;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

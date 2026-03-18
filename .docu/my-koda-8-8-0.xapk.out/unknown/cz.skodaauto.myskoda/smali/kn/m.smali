.class public final Lkn/m;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lkn/m;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lkn/m;->g:Ll2/b1;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lkn/m;->f:I

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    const-string v3, "it"

    .line 6
    .line 7
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    iget-object p0, p0, Lkn/m;->g:Ll2/b1;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast p1, Lt3/y;

    .line 15
    .line 16
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p1, v1, v2}, Lt3/y;->R(J)J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    new-instance p1, Ld3/b;

    .line 24
    .line 25
    invoke-direct {p1, v0, v1}, Ld3/b;-><init>(J)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-object v4

    .line 32
    :pswitch_0
    check-cast p1, Landroid/content/res/Configuration;

    .line 33
    .line 34
    new-instance v0, Landroid/content/res/Configuration;

    .line 35
    .line 36
    invoke-direct {v0, p1}, Landroid/content/res/Configuration;-><init>(Landroid/content/res/Configuration;)V

    .line 37
    .line 38
    .line 39
    sget-object p1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 40
    .line 41
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v4

    .line 45
    :pswitch_1
    check-cast p1, Lt3/y;

    .line 46
    .line 47
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-interface {p1, v1, v2}, Lt3/y;->R(J)J

    .line 51
    .line 52
    .line 53
    move-result-wide v0

    .line 54
    invoke-interface {p1}, Lt3/y;->h()J

    .line 55
    .line 56
    .line 57
    move-result-wide v2

    .line 58
    invoke-static {v2, v3}, Lkp/f9;->c(J)J

    .line 59
    .line 60
    .line 61
    move-result-wide v2

    .line 62
    invoke-static {v0, v1, v2, v3}, Ljp/cf;->c(JJ)Ld3/c;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    return-object v4

    .line 70
    :pswitch_2
    check-cast p1, Lt4/c;

    .line 71
    .line 72
    const-string v0, "$this$offset"

    .line 73
    .line 74
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    check-cast p0, Ld3/c;

    .line 82
    .line 83
    iget p0, p0, Ld3/c;->a:F

    .line 84
    .line 85
    float-to-int p0, p0

    .line 86
    const/4 p1, 0x0

    .line 87
    invoke-static {p0, p1}, Lkp/d9;->a(II)J

    .line 88
    .line 89
    .line 90
    move-result-wide p0

    .line 91
    new-instance v0, Lt4/j;

    .line 92
    .line 93
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 94
    .line 95
    .line 96
    return-object v0

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

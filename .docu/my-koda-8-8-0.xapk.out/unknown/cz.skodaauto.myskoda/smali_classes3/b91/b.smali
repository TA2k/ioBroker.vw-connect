.class public final Lb91/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:Lm6/g;

.field public final c:Lyy0/i;


# direct methods
.method public constructor <init>(Landroid/content/Context;I)V
    .locals 2

    .line 1
    packed-switch p2, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    sget-object p2, Lb91/c;->b:Lp6/b;

    .line 5
    .line 6
    sget-object v0, Lb91/c;->a:[Lhy0/z;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    aget-object v0, v0, v1

    .line 10
    .line 11
    invoke-virtual {p2, p1, v0}, Lp6/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lm6/g;

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    const/16 p2, 0x1f4

    .line 21
    .line 22
    iput p2, p0, Lb91/b;->a:I

    .line 23
    .line 24
    iput-object p1, p0, Lb91/b;->b:Lm6/g;

    .line 25
    .line 26
    invoke-interface {p1}, Lm6/g;->getData()Lyy0/i;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lac/l;

    .line 31
    .line 32
    const/4 v0, 0x5

    .line 33
    invoke-direct {p2, v0, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Lb91/b;->c:Lyy0/i;

    .line 41
    .line 42
    return-void

    .line 43
    :pswitch_0
    sget-object p2, Lb91/e;->b:Lp6/b;

    .line 44
    .line 45
    sget-object v0, Lb91/e;->a:[Lhy0/z;

    .line 46
    .line 47
    const/4 v1, 0x0

    .line 48
    aget-object v0, v0, v1

    .line 49
    .line 50
    invoke-virtual {p2, p1, v0}, Lp6/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    check-cast p1, Lm6/g;

    .line 55
    .line 56
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 57
    .line 58
    .line 59
    const/16 p2, 0x1f4

    .line 60
    .line 61
    iput p2, p0, Lb91/b;->a:I

    .line 62
    .line 63
    iput-object p1, p0, Lb91/b;->b:Lm6/g;

    .line 64
    .line 65
    invoke-interface {p1}, Lm6/g;->getData()Lyy0/i;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    new-instance p2, Lac/l;

    .line 70
    .line 71
    const/4 v0, 0x6

    .line 72
    invoke-direct {p2, v0, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    invoke-static {p2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    iput-object p1, p0, Lb91/b;->c:Lyy0/i;

    .line 80
    .line 81
    return-void

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

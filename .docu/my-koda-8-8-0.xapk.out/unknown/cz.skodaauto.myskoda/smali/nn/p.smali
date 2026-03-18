.class public final Lnn/p;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:Lnn/t;

.field public final synthetic g:Z

.field public final synthetic h:Lnn/s;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lnn/b;

.field public final synthetic l:Lnn/a;


# direct methods
.method public constructor <init>(Lnn/t;ZLnn/s;Lay0/k;Lay0/k;Lnn/b;Lnn/a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lnn/p;->f:Lnn/t;

    .line 2
    .line 3
    iput-boolean p2, p0, Lnn/p;->g:Z

    .line 4
    .line 5
    iput-object p3, p0, Lnn/p;->h:Lnn/s;

    .line 6
    .line 7
    iput-object p4, p0, Lnn/p;->i:Lay0/k;

    .line 8
    .line 9
    iput-object p5, p0, Lnn/p;->j:Lay0/k;

    .line 10
    .line 11
    iput-object p6, p0, Lnn/p;->k:Lnn/b;

    .line 12
    .line 13
    iput-object p7, p0, Lnn/p;->l:Lnn/a;

    .line 14
    .line 15
    const/4 p1, 0x3

    .line 16
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    check-cast p1, Landroidx/compose/foundation/layout/c;

    .line 2
    .line 3
    move-object v8, p2

    .line 4
    check-cast v8, Ll2/o;

    .line 5
    .line 6
    check-cast p3, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    const-string p3, "$this$BoxWithConstraints"

    .line 13
    .line 14
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-wide v0, p1, Landroidx/compose/foundation/layout/c;->b:J

    .line 18
    .line 19
    and-int/lit8 p3, p2, 0xe

    .line 20
    .line 21
    if-nez p3, :cond_1

    .line 22
    .line 23
    move-object p3, v8

    .line 24
    check-cast p3, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    const/4 p1, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p1, 0x2

    .line 35
    :goto_0
    or-int/2addr p2, p1

    .line 36
    :cond_1
    and-int/lit8 p1, p2, 0x5b

    .line 37
    .line 38
    const/16 p2, 0x12

    .line 39
    .line 40
    if-ne p1, p2, :cond_3

    .line 41
    .line 42
    move-object p1, v8

    .line 43
    check-cast p1, Ll2/t;

    .line 44
    .line 45
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    if-nez p2, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 53
    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_3
    :goto_1
    invoke-static {v0, v1}, Lt4/a;->f(J)Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    const/4 p2, -0x2

    .line 61
    const/4 p3, -0x1

    .line 62
    if-eqz p1, :cond_4

    .line 63
    .line 64
    move p1, p3

    .line 65
    goto :goto_2

    .line 66
    :cond_4
    move p1, p2

    .line 67
    :goto_2
    invoke-static {v0, v1}, Lt4/a;->e(J)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_5

    .line 72
    .line 73
    move p2, p3

    .line 74
    :cond_5
    new-instance v1, Landroid/widget/FrameLayout$LayoutParams;

    .line 75
    .line 76
    invoke-direct {v1, p1, p2}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V

    .line 77
    .line 78
    .line 79
    iget-object v7, p0, Lnn/p;->l:Lnn/a;

    .line 80
    .line 81
    const v9, 0x90001c0

    .line 82
    .line 83
    .line 84
    iget-object v0, p0, Lnn/p;->f:Lnn/t;

    .line 85
    .line 86
    iget-boolean v2, p0, Lnn/p;->g:Z

    .line 87
    .line 88
    iget-object v3, p0, Lnn/p;->h:Lnn/s;

    .line 89
    .line 90
    iget-object v4, p0, Lnn/p;->i:Lay0/k;

    .line 91
    .line 92
    iget-object v5, p0, Lnn/p;->j:Lay0/k;

    .line 93
    .line 94
    iget-object v6, p0, Lnn/p;->k:Lnn/b;

    .line 95
    .line 96
    invoke-static/range {v0 .. v9}, Lnn/q;->a(Lnn/t;Landroid/widget/FrameLayout$LayoutParams;ZLnn/s;Lay0/k;Lay0/k;Lnn/b;Lnn/a;Ll2/o;I)V

    .line 97
    .line 98
    .line 99
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0
.end method

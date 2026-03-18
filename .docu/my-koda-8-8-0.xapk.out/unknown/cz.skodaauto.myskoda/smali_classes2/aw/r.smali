.class public final Law/r;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:Law/w;

.field public final synthetic g:Z

.field public final synthetic h:Law/v;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Law/b;

.field public final synthetic l:Law/a;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:I


# direct methods
.method public constructor <init>(Law/w;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Law/r;->f:Law/w;

    .line 2
    .line 3
    iput-boolean p2, p0, Law/r;->g:Z

    .line 4
    .line 5
    iput-object p3, p0, Law/r;->h:Law/v;

    .line 6
    .line 7
    iput-object p4, p0, Law/r;->i:Lay0/k;

    .line 8
    .line 9
    iput-object p5, p0, Law/r;->j:Lay0/k;

    .line 10
    .line 11
    iput-object p6, p0, Law/r;->k:Law/b;

    .line 12
    .line 13
    iput-object p7, p0, Law/r;->l:Law/a;

    .line 14
    .line 15
    iput-object p8, p0, Law/r;->m:Lay0/k;

    .line 16
    .line 17
    iput p9, p0, Law/r;->n:I

    .line 18
    .line 19
    const/4 p1, 0x3

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Landroidx/compose/foundation/layout/c;

    .line 2
    .line 3
    move-object v9, p2

    .line 4
    check-cast v9, Ll2/o;

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
    move-object p3, v9

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
    move-object p1, v9

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
    iget p1, p0, Law/r;->n:I

    .line 80
    .line 81
    and-int/lit8 p2, p1, 0xe

    .line 82
    .line 83
    const p3, 0x90001c0

    .line 84
    .line 85
    .line 86
    or-int/2addr p2, p3

    .line 87
    shl-int/lit8 p1, p1, 0x3

    .line 88
    .line 89
    and-int/lit16 p3, p1, 0x1c00

    .line 90
    .line 91
    or-int/2addr p2, p3

    .line 92
    const p3, 0xe000

    .line 93
    .line 94
    .line 95
    and-int/2addr p3, p1

    .line 96
    or-int/2addr p2, p3

    .line 97
    const/high16 p3, 0x70000

    .line 98
    .line 99
    and-int/2addr p3, p1

    .line 100
    or-int/2addr p2, p3

    .line 101
    const/high16 p3, 0x380000

    .line 102
    .line 103
    and-int/2addr p3, p1

    .line 104
    or-int/2addr p2, p3

    .line 105
    const/high16 p3, 0x70000000

    .line 106
    .line 107
    and-int/2addr p1, p3

    .line 108
    or-int v10, p2, p1

    .line 109
    .line 110
    iget-object v0, p0, Law/r;->f:Law/w;

    .line 111
    .line 112
    iget-boolean v2, p0, Law/r;->g:Z

    .line 113
    .line 114
    iget-object v3, p0, Law/r;->h:Law/v;

    .line 115
    .line 116
    iget-object v4, p0, Law/r;->i:Lay0/k;

    .line 117
    .line 118
    iget-object v5, p0, Law/r;->j:Lay0/k;

    .line 119
    .line 120
    iget-object v6, p0, Law/r;->k:Law/b;

    .line 121
    .line 122
    iget-object v7, p0, Law/r;->l:Law/a;

    .line 123
    .line 124
    iget-object v8, p0, Law/r;->m:Lay0/k;

    .line 125
    .line 126
    invoke-static/range {v0 .. v10}, Ljp/m1;->a(Law/w;Landroid/widget/FrameLayout$LayoutParams;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;Ll2/o;I)V

    .line 127
    .line 128
    .line 129
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    return-object p0
.end method

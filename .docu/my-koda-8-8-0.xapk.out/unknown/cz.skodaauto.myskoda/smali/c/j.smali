.class public abstract Lc/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lay/b;

    .line 2
    .line 3
    const/16 v1, 0x16

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lay/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lc/j;->a:Ll2/e0;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Ll2/o;)Lb/j0;
    .locals 5

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    sget-object v0, Lc/j;->a:Ll2/e0;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lb/j0;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x0

    .line 13
    if-nez v0, :cond_4

    .line 14
    .line 15
    const v0, 0x48071ead

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 19
    .line 20
    .line 21
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->f:Ll2/u2;

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Landroid/view/View;

    .line 28
    .line 29
    const-string v3, "<this>"

    .line 30
    .line 31
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    if-eqz v0, :cond_3

    .line 35
    .line 36
    const v3, 0x7f0a0303

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v3}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    instance-of v4, v3, Lb/j0;

    .line 44
    .line 45
    if-eqz v4, :cond_0

    .line 46
    .line 47
    check-cast v3, Lb/j0;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_0
    move-object v3, v1

    .line 51
    :goto_1
    if-eqz v3, :cond_1

    .line 52
    .line 53
    move-object v0, v3

    .line 54
    goto :goto_2

    .line 55
    :cond_1
    invoke-static {v0}, Lkp/o8;->b(Landroid/view/View;)Landroid/view/ViewParent;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    instance-of v3, v0, Landroid/view/View;

    .line 60
    .line 61
    if-eqz v3, :cond_2

    .line 62
    .line 63
    check-cast v0, Landroid/view/View;

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    move-object v0, v1

    .line 67
    goto :goto_0

    .line 68
    :cond_3
    move-object v0, v1

    .line 69
    :goto_2
    invoke-virtual {p0, v2}, Ll2/t;->q(Z)V

    .line 70
    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    const v3, 0x4807151c

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0, v3}, Ll2/t;->Y(I)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0, v2}, Ll2/t;->q(Z)V

    .line 80
    .line 81
    .line 82
    :goto_3
    if-nez v0, :cond_7

    .line 83
    .line 84
    const v0, 0x48072680    # 138394.0f

    .line 85
    .line 86
    .line 87
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 88
    .line 89
    .line 90
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 91
    .line 92
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    check-cast v0, Landroid/content/Context;

    .line 97
    .line 98
    :goto_4
    instance-of v3, v0, Landroid/content/ContextWrapper;

    .line 99
    .line 100
    if-eqz v3, :cond_6

    .line 101
    .line 102
    instance-of v3, v0, Lb/j0;

    .line 103
    .line 104
    if-eqz v3, :cond_5

    .line 105
    .line 106
    move-object v1, v0

    .line 107
    goto :goto_5

    .line 108
    :cond_5
    check-cast v0, Landroid/content/ContextWrapper;

    .line 109
    .line 110
    invoke-virtual {v0}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    goto :goto_4

    .line 115
    :cond_6
    :goto_5
    check-cast v1, Lb/j0;

    .line 116
    .line 117
    invoke-virtual {p0, v2}, Ll2/t;->q(Z)V

    .line 118
    .line 119
    .line 120
    return-object v1

    .line 121
    :cond_7
    const v1, 0x4807156d

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0, v1}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0, v2}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    return-object v0
.end method

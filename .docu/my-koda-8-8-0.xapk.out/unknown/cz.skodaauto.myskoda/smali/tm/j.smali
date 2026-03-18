.class public final Ltm/j;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/util/ArrayList;

.field public final synthetic h:Lg4/d;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Lg4/d;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltm/j;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ltm/j;->g:Ljava/util/ArrayList;

    .line 4
    .line 5
    iput-object p2, p0, Ltm/j;->h:Lg4/d;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltm/j;->f:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ltm/e;

    .line 11
    .line 12
    const-string v2, "content"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, v0, Ltm/j;->g:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    iget v2, v1, Ltm/e;->a:I

    .line 23
    .line 24
    int-to-float v2, v2

    .line 25
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    invoke-virtual {v3}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    iget v3, v3, Landroid/util/DisplayMetrics;->scaledDensity:F

    .line 34
    .line 35
    div-float/2addr v2, v3

    .line 36
    const-wide v3, 0x100000000L

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    invoke-static {v3, v4, v2}, Lgq/b;->e(JF)J

    .line 42
    .line 43
    .line 44
    move-result-wide v5

    .line 45
    iget v2, v1, Ltm/e;->b:I

    .line 46
    .line 47
    int-to-float v2, v2

    .line 48
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 49
    .line 50
    .line 51
    move-result-object v7

    .line 52
    invoke-virtual {v7}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 53
    .line 54
    .line 55
    move-result-object v7

    .line 56
    iget v7, v7, Landroid/util/DisplayMetrics;->scaledDensity:F

    .line 57
    .line 58
    div-float/2addr v2, v7

    .line 59
    invoke-static {v3, v4, v2}, Lgq/b;->e(JF)J

    .line 60
    .line 61
    .line 62
    move-result-wide v2

    .line 63
    invoke-static {v5, v6}, Lt4/o;->c(J)F

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    const/4 v7, 0x0

    .line 68
    cmpg-float v4, v4, v7

    .line 69
    .line 70
    if-nez v4, :cond_0

    .line 71
    .line 72
    invoke-static {v2, v3}, Lt4/o;->c(J)F

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    cmpg-float v4, v4, v7

    .line 77
    .line 78
    if-nez v4, :cond_0

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_0
    new-instance v7, Lg4/t;

    .line 82
    .line 83
    new-instance v12, Lr4/q;

    .line 84
    .line 85
    invoke-direct {v12, v5, v6, v2, v3}, Lr4/q;-><init>(JJ)V

    .line 86
    .line 87
    .line 88
    sget-wide v10, Lt4/o;->c:J

    .line 89
    .line 90
    const/4 v15, 0x0

    .line 91
    const/16 v17, 0x0

    .line 92
    .line 93
    const/high16 v8, -0x80000000

    .line 94
    .line 95
    const/4 v13, 0x0

    .line 96
    const/4 v14, 0x0

    .line 97
    move v9, v8

    .line 98
    move/from16 v16, v8

    .line 99
    .line 100
    invoke-direct/range {v7 .. v17}, Lg4/t;-><init>(IIJLr4/q;Lg4/w;Lr4/i;IILr4/s;)V

    .line 101
    .line 102
    .line 103
    iget v9, v1, Ltm/e;->c:I

    .line 104
    .line 105
    iget v10, v1, Ltm/e;->d:I

    .line 106
    .line 107
    iget-object v0, v0, Ltm/j;->h:Lg4/d;

    .line 108
    .line 109
    iget-object v0, v0, Lg4/d;->f:Ljava/util/ArrayList;

    .line 110
    .line 111
    move-object v8, v7

    .line 112
    new-instance v7, Lg4/c;

    .line 113
    .line 114
    const/4 v11, 0x0

    .line 115
    const/16 v12, 0x8

    .line 116
    .line 117
    invoke-direct/range {v7 .. v12}, Lg4/c;-><init>(Lg4/b;IILjava/lang/String;I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object v0

    .line 126
    :pswitch_0
    move-object/from16 v1, p1

    .line 127
    .line 128
    check-cast v1, Ltm/c;

    .line 129
    .line 130
    const-string v2, "content"

    .line 131
    .line 132
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    iget-object v2, v0, Ltm/j;->g:Ljava/util/ArrayList;

    .line 136
    .line 137
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    iget-object v2, v1, Ltm/c;->a:Ljava/lang/String;

    .line 141
    .line 142
    iget v3, v1, Ltm/c;->b:I

    .line 143
    .line 144
    iget v1, v1, Ltm/c;->c:I

    .line 145
    .line 146
    iget-object v0, v0, Ltm/j;->h:Lg4/d;

    .line 147
    .line 148
    const-string v4, "androidx.compose.foundation.text.inlineContent"

    .line 149
    .line 150
    invoke-virtual {v0, v4, v2, v3, v1}, Lg4/d;->a(Ljava/lang/String;Ljava/lang/String;II)V

    .line 151
    .line 152
    .line 153
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 154
    .line 155
    return-object v0

    .line 156
    nop

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

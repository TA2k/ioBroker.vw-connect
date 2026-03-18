.class public final Lw4/j;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lw4/j;

.field public static final h:Lw4/j;

.field public static final i:Lw4/j;

.field public static final j:Lw4/j;

.field public static final k:Lw4/j;

.field public static final l:Lw4/j;

.field public static final m:Lw4/j;

.field public static final n:Lw4/j;

.field public static final o:Lw4/j;

.field public static final p:Lw4/j;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lw4/j;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lw4/j;->g:Lw4/j;

    .line 9
    .line 10
    new-instance v0, Lw4/j;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lw4/j;->h:Lw4/j;

    .line 17
    .line 18
    new-instance v0, Lw4/j;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lw4/j;->i:Lw4/j;

    .line 25
    .line 26
    new-instance v0, Lw4/j;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Lw4/j;->j:Lw4/j;

    .line 33
    .line 34
    new-instance v0, Lw4/j;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lw4/j;->k:Lw4/j;

    .line 41
    .line 42
    new-instance v0, Lw4/j;

    .line 43
    .line 44
    const/4 v2, 0x5

    .line 45
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Lw4/j;->l:Lw4/j;

    .line 49
    .line 50
    new-instance v0, Lw4/j;

    .line 51
    .line 52
    const/4 v2, 0x6

    .line 53
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 54
    .line 55
    .line 56
    sput-object v0, Lw4/j;->m:Lw4/j;

    .line 57
    .line 58
    new-instance v0, Lw4/j;

    .line 59
    .line 60
    const/4 v2, 0x7

    .line 61
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 62
    .line 63
    .line 64
    sput-object v0, Lw4/j;->n:Lw4/j;

    .line 65
    .line 66
    new-instance v0, Lw4/j;

    .line 67
    .line 68
    const/16 v2, 0x8

    .line 69
    .line 70
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 71
    .line 72
    .line 73
    sput-object v0, Lw4/j;->o:Lw4/j;

    .line 74
    .line 75
    new-instance v0, Lw4/j;

    .line 76
    .line 77
    const/16 v2, 0x9

    .line 78
    .line 79
    invoke-direct {v0, v1, v2}, Lw4/j;-><init>(II)V

    .line 80
    .line 81
    .line 82
    sput-object v0, Lw4/j;->p:Lw4/j;

    .line 83
    .line 84
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lw4/j;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lw4/j;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lv3/h0;

    .line 7
    .line 8
    check-cast p2, Lt4/m;

    .line 9
    .line 10
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    const/4 p2, 0x1

    .line 21
    if-ne p1, p2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance p0, La8/r0;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    const/4 p2, 0x0

    .line 31
    :goto_0
    invoke-virtual {p0, p2}, Landroid/view/View;->setLayoutDirection(I)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_0
    check-cast p1, Lv3/h0;

    .line 38
    .line 39
    check-cast p2, Lra/f;

    .line 40
    .line 41
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0, p2}, Lw4/g;->setSavedStateRegistryOwner(Lra/f;)V

    .line 46
    .line 47
    .line 48
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_1
    check-cast p1, Lv3/h0;

    .line 52
    .line 53
    check-cast p2, Landroidx/lifecycle/x;

    .line 54
    .line 55
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-virtual {p0, p2}, Lw4/g;->setLifecycleOwner(Landroidx/lifecycle/x;)V

    .line 60
    .line 61
    .line 62
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_2
    check-cast p1, Lv3/h0;

    .line 66
    .line 67
    check-cast p2, Lt4/c;

    .line 68
    .line 69
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-virtual {p0, p2}, Lw4/g;->setDensity(Lt4/c;)V

    .line 74
    .line 75
    .line 76
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_3
    check-cast p1, Lv3/h0;

    .line 80
    .line 81
    check-cast p2, Lx2/s;

    .line 82
    .line 83
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-virtual {p0, p2}, Lw4/g;->setModifier(Lx2/s;)V

    .line 88
    .line 89
    .line 90
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_4
    check-cast p1, Lv3/h0;

    .line 94
    .line 95
    check-cast p2, Lay0/k;

    .line 96
    .line 97
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-virtual {p0, p2}, Lw4/o;->setReleaseBlock(Lay0/k;)V

    .line 102
    .line 103
    .line 104
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 105
    .line 106
    return-object p0

    .line 107
    :pswitch_5
    check-cast p1, Lv3/h0;

    .line 108
    .line 109
    check-cast p2, Lay0/k;

    .line 110
    .line 111
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {p0, p2}, Lw4/o;->setUpdateBlock(Lay0/k;)V

    .line 116
    .line 117
    .line 118
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_6
    check-cast p1, Lv3/h0;

    .line 122
    .line 123
    check-cast p2, Lay0/k;

    .line 124
    .line 125
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-virtual {p0, p2}, Lw4/o;->setReleaseBlock(Lay0/k;)V

    .line 130
    .line 131
    .line 132
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_7
    check-cast p1, Lv3/h0;

    .line 136
    .line 137
    check-cast p2, Lay0/k;

    .line 138
    .line 139
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    invoke-virtual {p0, p2}, Lw4/o;->setUpdateBlock(Lay0/k;)V

    .line 144
    .line 145
    .line 146
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 147
    .line 148
    return-object p0

    .line 149
    :pswitch_8
    check-cast p1, Lv3/h0;

    .line 150
    .line 151
    check-cast p2, Lay0/k;

    .line 152
    .line 153
    invoke-static {p1}, Landroidx/compose/ui/viewinterop/a;->c(Lv3/h0;)Lw4/o;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-virtual {p0, p2}, Lw4/o;->setResetBlock(Lay0/k;)V

    .line 158
    .line 159
    .line 160
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 161
    .line 162
    return-object p0

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

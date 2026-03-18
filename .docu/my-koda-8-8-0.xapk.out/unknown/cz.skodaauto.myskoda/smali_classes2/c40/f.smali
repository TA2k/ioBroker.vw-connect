.class public final Lc40/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Lc40/f;

.field public static final f:Lc40/f;

.field public static final g:Lc40/f;

.field public static final h:Lc40/f;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lc40/f;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lc40/f;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lc40/f;->e:Lc40/f;

    .line 8
    .line 9
    new-instance v0, Lc40/f;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lc40/f;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lc40/f;->f:Lc40/f;

    .line 16
    .line 17
    new-instance v0, Lc40/f;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lc40/f;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lc40/f;->g:Lc40/f;

    .line 24
    .line 25
    new-instance v0, Lc40/f;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lc40/f;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lc40/f;->h:Lc40/f;

    .line 32
    .line 33
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lc40/f;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lc40/f;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lz4/e;

    .line 7
    .line 8
    const-string p0, "$this$constrainAs"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 14
    .line 15
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 16
    .line 17
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v3, 0x6

    .line 21
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 25
    .line 26
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 27
    .line 28
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 32
    .line 33
    iget-object p1, v0, Lz4/f;->g:Lz4/g;

    .line 34
    .line 35
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 42
    .line 43
    const-string p0, "$this$constrainAs"

    .line 44
    .line 45
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 49
    .line 50
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 51
    .line 52
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    const/4 v3, 0x6

    .line 56
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 57
    .line 58
    .line 59
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 60
    .line 61
    iget-object p1, v0, Lz4/f;->e:Lz4/g;

    .line 62
    .line 63
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 64
    .line 65
    .line 66
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_1
    check-cast p1, Lz4/e;

    .line 70
    .line 71
    const-string p0, "$this$constrainAs"

    .line 72
    .line 73
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 77
    .line 78
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 79
    .line 80
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    const/4 v3, 0x6

    .line 84
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 85
    .line 86
    .line 87
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 88
    .line 89
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 90
    .line 91
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 92
    .line 93
    .line 94
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 95
    .line 96
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 97
    .line 98
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 99
    .line 100
    .line 101
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 102
    .line 103
    iget-object p1, v0, Lz4/f;->g:Lz4/g;

    .line 104
    .line 105
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 106
    .line 107
    .line 108
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_2
    check-cast p1, Lz4/e;

    .line 112
    .line 113
    const-string p0, "$this$constrainAs"

    .line 114
    .line 115
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 119
    .line 120
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 121
    .line 122
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 123
    .line 124
    const/4 v2, 0x0

    .line 125
    const/4 v3, 0x6

    .line 126
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 127
    .line 128
    .line 129
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 130
    .line 131
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 132
    .line 133
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 134
    .line 135
    .line 136
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 137
    .line 138
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 139
    .line 140
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 141
    .line 142
    .line 143
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 144
    .line 145
    iget-object p1, v0, Lz4/f;->g:Lz4/g;

    .line 146
    .line 147
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 148
    .line 149
    .line 150
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 151
    .line 152
    return-object p0

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

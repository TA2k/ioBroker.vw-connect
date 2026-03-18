.class public final Lwk/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Lwk/d;

.field public static final f:Lwk/d;

.field public static final g:Lwk/d;

.field public static final h:Lwk/d;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lwk/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lwk/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lwk/d;->e:Lwk/d;

    .line 8
    .line 9
    new-instance v0, Lwk/d;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lwk/d;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lwk/d;->f:Lwk/d;

    .line 16
    .line 17
    new-instance v0, Lwk/d;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lwk/d;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lwk/d;->g:Lwk/d;

    .line 24
    .line 25
    new-instance v0, Lwk/d;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lwk/d;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lwk/d;->h:Lwk/d;

    .line 32
    .line 33
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lwk/d;->d:I

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
    iget p0, p0, Lwk/d;->d:I

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
    iget-object p1, p1, Lz4/e;->c:Lz4/f;

    .line 51
    .line 52
    iget-object p1, p1, Lz4/f;->d:Lz4/h;

    .line 53
    .line 54
    const/4 v0, 0x0

    .line 55
    const/4 v1, 0x6

    .line 56
    invoke-static {p0, p1, v0, v1}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 57
    .line 58
    .line 59
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_1
    check-cast p1, Lz4/e;

    .line 63
    .line 64
    const-string p0, "$this$constrainAs"

    .line 65
    .line 66
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 70
    .line 71
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 72
    .line 73
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 74
    .line 75
    const/4 v2, 0x0

    .line 76
    const/4 v3, 0x6

    .line 77
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 81
    .line 82
    iget-object p1, v0, Lz4/f;->e:Lz4/g;

    .line 83
    .line 84
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 85
    .line 86
    .line 87
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_2
    check-cast p1, Lz4/e;

    .line 91
    .line 92
    const-string p0, "$this$constrainAs"

    .line 93
    .line 94
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 98
    .line 99
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 100
    .line 101
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 102
    .line 103
    const/4 v2, 0x0

    .line 104
    const/4 v3, 0x6

    .line 105
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 106
    .line 107
    .line 108
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 109
    .line 110
    iget-object p1, v0, Lz4/f;->e:Lz4/g;

    .line 111
    .line 112
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 113
    .line 114
    .line 115
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    return-object p0

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

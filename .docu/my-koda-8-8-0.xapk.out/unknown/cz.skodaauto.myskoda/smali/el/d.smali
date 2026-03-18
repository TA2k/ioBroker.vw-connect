.class public final Lel/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Lel/d;

.field public static final f:Lel/d;

.field public static final g:Lel/d;

.field public static final h:Lel/d;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lel/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lel/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lel/d;->e:Lel/d;

    .line 8
    .line 9
    new-instance v0, Lel/d;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lel/d;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lel/d;->f:Lel/d;

    .line 16
    .line 17
    new-instance v0, Lel/d;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lel/d;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lel/d;->g:Lel/d;

    .line 24
    .line 25
    new-instance v0, Lel/d;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lel/d;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lel/d;->h:Lel/d;

    .line 32
    .line 33
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lel/d;->d:I

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
    iget p0, p0, Lel/d;->d:I

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
    iget-object p0, p1, Lz4/e;->c:Lz4/f;

    .line 14
    .line 15
    invoke-static {p1, p0}, Lz4/e;->a(Lz4/e;Lz4/f;)V

    .line 16
    .line 17
    .line 18
    iget-object p1, p1, Lz4/e;->g:Ly41/a;

    .line 19
    .line 20
    iget-object p0, p0, Lz4/f;->g:Lz4/g;

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    const/4 v1, 0x6

    .line 24
    invoke-static {p1, p0, v0, v1}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 31
    .line 32
    const-string p0, "$this$constrainAs"

    .line 33
    .line 34
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 38
    .line 39
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 40
    .line 41
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    const/4 v3, 0x6

    .line 45
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 49
    .line 50
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 51
    .line 52
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 53
    .line 54
    .line 55
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_1
    check-cast p1, Lz4/e;

    .line 59
    .line 60
    const-string p0, "$this$constrainAs"

    .line 61
    .line 62
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 66
    .line 67
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 68
    .line 69
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    const/4 v3, 0x6

    .line 73
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 74
    .line 75
    .line 76
    invoke-static {p1, v0}, Lz4/e;->b(Lz4/e;Lz4/f;)V

    .line 77
    .line 78
    .line 79
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object p0

    .line 82
    :pswitch_2
    check-cast p1, Lz4/e;

    .line 83
    .line 84
    const-string p0, "$this$constrainAs"

    .line 85
    .line 86
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 90
    .line 91
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 92
    .line 93
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 94
    .line 95
    const/4 v2, 0x0

    .line 96
    const/4 v3, 0x6

    .line 97
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 98
    .line 99
    .line 100
    invoke-static {p1, v0}, Lz4/e;->b(Lz4/e;Lz4/f;)V

    .line 101
    .line 102
    .line 103
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

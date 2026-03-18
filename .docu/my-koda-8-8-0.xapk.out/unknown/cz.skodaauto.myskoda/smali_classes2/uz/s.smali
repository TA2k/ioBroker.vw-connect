.class public final Luz/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz4/f;

.field public final synthetic f:Lz4/f;


# direct methods
.method public synthetic constructor <init>(Lz4/f;Lz4/f;I)V
    .locals 0

    .line 1
    iput p3, p0, Luz/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luz/s;->e:Lz4/f;

    .line 4
    .line 5
    iput-object p2, p0, Luz/s;->f:Lz4/f;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Luz/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lz4/e;

    .line 7
    .line 8
    const-string v0, "$this$constrainAs"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p1, Lz4/e;->e:Ly41/a;

    .line 14
    .line 15
    iget-object v1, p1, Lz4/e;->c:Lz4/f;

    .line 16
    .line 17
    iget-object v2, v1, Lz4/f;->e:Lz4/g;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x6

    .line 21
    invoke-static {v0, v2, v3, v4}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p1, Lz4/e;->d:Ly7/k;

    .line 25
    .line 26
    iget-object v1, v1, Lz4/f;->d:Lz4/h;

    .line 27
    .line 28
    invoke-static {v0, v1, v3, v4}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p1, Lz4/e;->f:Ly7/k;

    .line 32
    .line 33
    iget-object v1, p0, Luz/s;->e:Lz4/f;

    .line 34
    .line 35
    iget-object v1, v1, Lz4/f;->d:Lz4/h;

    .line 36
    .line 37
    invoke-static {v0, v1, v3, v4}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 38
    .line 39
    .line 40
    iget-object v0, p1, Lz4/e;->g:Ly41/a;

    .line 41
    .line 42
    iget-object p0, p0, Luz/s;->f:Lz4/f;

    .line 43
    .line 44
    iget-object p0, p0, Lz4/f;->e:Lz4/g;

    .line 45
    .line 46
    invoke-static {v0, p0, v3, v4}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 47
    .line 48
    .line 49
    new-instance p0, Lz4/n;

    .line 50
    .line 51
    const-string v0, "spread"

    .line 52
    .line 53
    invoke-direct {p0, v0}, Lz4/n;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1, p0}, Lz4/e;->c(Lz4/n;)V

    .line 57
    .line 58
    .line 59
    new-instance p0, Lz4/n;

    .line 60
    .line 61
    invoke-direct {p0, v0}, Lz4/n;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget-object v0, p1, Lz4/e;->i:Lz4/c;

    .line 65
    .line 66
    sget-object v1, Lz4/e;->j:[Lhy0/z;

    .line 67
    .line 68
    const/4 v2, 0x1

    .line 69
    aget-object v1, v1, v2

    .line 70
    .line 71
    invoke-virtual {v0, p1, v1, p0}, Ldy0/a;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 78
    .line 79
    const-string v0, "$this$constrainAs"

    .line 80
    .line 81
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    iget-object v0, p1, Lz4/e;->e:Ly41/a;

    .line 85
    .line 86
    iget-object v1, p0, Luz/s;->e:Lz4/f;

    .line 87
    .line 88
    iget-object v2, v1, Lz4/f;->e:Lz4/g;

    .line 89
    .line 90
    const/4 v3, 0x0

    .line 91
    const/4 v4, 0x6

    .line 92
    invoke-static {v0, v2, v3, v4}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 93
    .line 94
    .line 95
    iget-object v0, p1, Lz4/e;->g:Ly41/a;

    .line 96
    .line 97
    iget-object v2, v1, Lz4/f;->g:Lz4/g;

    .line 98
    .line 99
    invoke-static {v0, v2, v3, v4}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 100
    .line 101
    .line 102
    iget-object v0, p1, Lz4/e;->d:Ly7/k;

    .line 103
    .line 104
    iget-object v1, v1, Lz4/f;->f:Lz4/h;

    .line 105
    .line 106
    invoke-static {v0, v1, v3, v4}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 107
    .line 108
    .line 109
    iget-object v0, p1, Lz4/e;->f:Ly7/k;

    .line 110
    .line 111
    iget-object p0, p0, Luz/s;->f:Lz4/f;

    .line 112
    .line 113
    iget-object p0, p0, Lz4/f;->d:Lz4/h;

    .line 114
    .line 115
    invoke-static {v0, p0, v3, v4}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 116
    .line 117
    .line 118
    new-instance p0, Lz4/n;

    .line 119
    .line 120
    const-string v0, "spread"

    .line 121
    .line 122
    invoke-direct {p0, v0}, Lz4/n;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p1, p0}, Lz4/e;->c(Lz4/n;)V

    .line 126
    .line 127
    .line 128
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    return-object p0

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

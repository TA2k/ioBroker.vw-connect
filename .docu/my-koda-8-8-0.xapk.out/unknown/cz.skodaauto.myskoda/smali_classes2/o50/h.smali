.class public final Lo50/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz4/f;

.field public final synthetic f:F

.field public final synthetic g:Ln50/f;

.field public final synthetic h:Lz4/f;

.field public final synthetic i:F


# direct methods
.method public constructor <init>(FLz4/f;Ln50/f;Lz4/f;F)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lo50/h;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lo50/h;->f:F

    iput-object p2, p0, Lo50/h;->e:Lz4/f;

    iput-object p3, p0, Lo50/h;->g:Ln50/f;

    iput-object p4, p0, Lo50/h;->h:Lz4/f;

    iput p5, p0, Lo50/h;->i:F

    return-void
.end method

.method public constructor <init>(Lz4/f;FLn50/f;Lz4/f;F)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lo50/h;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo50/h;->e:Lz4/f;

    iput p2, p0, Lo50/h;->f:F

    iput-object p3, p0, Lo50/h;->g:Ln50/f;

    iput-object p4, p0, Lo50/h;->h:Lz4/f;

    iput p5, p0, Lo50/h;->i:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lo50/h;->d:I

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
    iget-object v0, p1, Lz4/e;->f:Ly7/k;

    .line 14
    .line 15
    new-instance v1, Lz4/n;

    .line 16
    .line 17
    const-string v2, "spread"

    .line 18
    .line 19
    invoke-direct {v1, v2}, Lz4/n;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, v1}, Lz4/e;->c(Lz4/n;)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p1, Lz4/e;->e:Ly41/a;

    .line 26
    .line 27
    iget-object v2, p0, Lo50/h;->e:Lz4/f;

    .line 28
    .line 29
    iget-object v2, v2, Lz4/f;->g:Lz4/g;

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x6

    .line 33
    invoke-static {v1, v2, v3, v4}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 34
    .line 35
    .line 36
    iget-object v1, p1, Lz4/e;->d:Ly7/k;

    .line 37
    .line 38
    iget-object v2, p1, Lz4/e;->c:Lz4/f;

    .line 39
    .line 40
    iget-object v3, v2, Lz4/f;->d:Lz4/h;

    .line 41
    .line 42
    iget v4, p0, Lo50/h;->f:F

    .line 43
    .line 44
    const/4 v5, 0x4

    .line 45
    invoke-static {v1, v3, v4, v5}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lo50/h;->g:Ln50/f;

    .line 49
    .line 50
    iget-boolean v3, v1, Ln50/f;->e:Z

    .line 51
    .line 52
    if-nez v3, :cond_1

    .line 53
    .line 54
    iget-boolean v1, v1, Ln50/f;->f:Z

    .line 55
    .line 56
    if-eqz v1, :cond_0

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    iget-object p0, v2, Lz4/f;->f:Lz4/h;

    .line 60
    .line 61
    invoke-static {v0, p0, v4, v5}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    :goto_0
    iget-object v1, p0, Lo50/h;->h:Lz4/f;

    .line 66
    .line 67
    iget-object v1, v1, Lz4/f;->d:Lz4/h;

    .line 68
    .line 69
    iget p0, p0, Lo50/h;->i:F

    .line 70
    .line 71
    invoke-static {v0, v1, p0, v5}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 72
    .line 73
    .line 74
    :goto_1
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 75
    .line 76
    iget-object p1, v2, Lz4/f;->g:Lz4/g;

    .line 77
    .line 78
    invoke-static {p0, p1, v4, v5}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 79
    .line 80
    .line 81
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 85
    .line 86
    const-string v0, "$this$constrainAs"

    .line 87
    .line 88
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    iget-object v0, p1, Lz4/e;->d:Ly7/k;

    .line 92
    .line 93
    new-instance v1, Lz4/n;

    .line 94
    .line 95
    const-string v2, "spread"

    .line 96
    .line 97
    invoke-direct {v1, v2}, Lz4/n;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p1, v1}, Lz4/e;->c(Lz4/n;)V

    .line 101
    .line 102
    .line 103
    iget-object v1, p1, Lz4/e;->e:Ly41/a;

    .line 104
    .line 105
    iget-object v2, p1, Lz4/e;->c:Lz4/f;

    .line 106
    .line 107
    iget-object v3, v2, Lz4/f;->e:Lz4/g;

    .line 108
    .line 109
    iget v4, p0, Lo50/h;->f:F

    .line 110
    .line 111
    const/4 v5, 0x4

    .line 112
    invoke-static {v1, v3, v4, v5}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 113
    .line 114
    .line 115
    iget-object p1, p1, Lz4/e;->f:Ly7/k;

    .line 116
    .line 117
    iget-object v1, p0, Lo50/h;->e:Lz4/f;

    .line 118
    .line 119
    iget-object v1, v1, Lz4/f;->d:Lz4/h;

    .line 120
    .line 121
    const/4 v3, 0x0

    .line 122
    const/4 v6, 0x6

    .line 123
    invoke-static {p1, v1, v3, v6}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 124
    .line 125
    .line 126
    iget-object p1, p0, Lo50/h;->g:Ln50/f;

    .line 127
    .line 128
    iget-object p1, p1, Ln50/f;->c:Ljava/lang/Integer;

    .line 129
    .line 130
    if-eqz p1, :cond_2

    .line 131
    .line 132
    iget-object p1, p0, Lo50/h;->h:Lz4/f;

    .line 133
    .line 134
    iget-object p1, p1, Lz4/f;->f:Lz4/h;

    .line 135
    .line 136
    iget p0, p0, Lo50/h;->i:F

    .line 137
    .line 138
    invoke-static {v0, p1, p0, v5}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_2
    iget-object p0, v2, Lz4/f;->d:Lz4/h;

    .line 143
    .line 144
    invoke-static {v0, p0, v4, v5}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 145
    .line 146
    .line 147
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    return-object p0

    .line 150
    nop

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

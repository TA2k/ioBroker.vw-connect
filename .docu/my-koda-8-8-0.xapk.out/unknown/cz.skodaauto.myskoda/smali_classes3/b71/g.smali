.class public final synthetic Lb71/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Z

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Llx0/e;

.field public final synthetic n:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Lh2/u7;Lx2/s;ZLh2/u8;Li1/l;Li1/l;Lt2/b;Lt2/b;Lt2/b;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lb71/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/g;->h:Ljava/lang/Object;

    iput-object p2, p0, Lb71/g;->e:Lx2/s;

    iput-boolean p3, p0, Lb71/g;->f:Z

    iput-object p4, p0, Lb71/g;->i:Ljava/lang/Object;

    iput-object p5, p0, Lb71/g;->j:Ljava/lang/Object;

    iput-object p6, p0, Lb71/g;->k:Ljava/lang/Object;

    iput-object p7, p0, Lb71/g;->l:Ljava/lang/Object;

    iput-object p8, p0, Lb71/g;->m:Llx0/e;

    iput-object p9, p0, Lb71/g;->n:Llx0/e;

    iput p10, p0, Lb71/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Lay0/a;Lay0/a;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lb71/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/g;->e:Lx2/s;

    iput-object p2, p0, Lb71/g;->h:Ljava/lang/Object;

    iput-object p3, p0, Lb71/g;->i:Ljava/lang/Object;

    iput-object p4, p0, Lb71/g;->j:Ljava/lang/Object;

    iput-object p5, p0, Lb71/g;->k:Ljava/lang/Object;

    iput-boolean p6, p0, Lb71/g;->f:Z

    iput-object p7, p0, Lb71/g;->l:Ljava/lang/Object;

    iput-object p8, p0, Lb71/g;->m:Llx0/e;

    iput-object p9, p0, Lb71/g;->n:Llx0/e;

    iput p10, p0, Lb71/g;->g:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lb71/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb71/g;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lh2/u7;

    .line 10
    .line 11
    iget-object v0, p0, Lb71/g;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lh2/u8;

    .line 15
    .line 16
    iget-object v0, p0, Lb71/g;->j:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v5, v0

    .line 19
    check-cast v5, Li1/l;

    .line 20
    .line 21
    iget-object v0, p0, Lb71/g;->k:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v6, v0

    .line 24
    check-cast v6, Li1/l;

    .line 25
    .line 26
    iget-object v0, p0, Lb71/g;->l:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v7, v0

    .line 29
    check-cast v7, Lt2/b;

    .line 30
    .line 31
    iget-object v0, p0, Lb71/g;->m:Llx0/e;

    .line 32
    .line 33
    move-object v8, v0

    .line 34
    check-cast v8, Lt2/b;

    .line 35
    .line 36
    iget-object v0, p0, Lb71/g;->n:Llx0/e;

    .line 37
    .line 38
    move-object v9, v0

    .line 39
    check-cast v9, Lt2/b;

    .line 40
    .line 41
    move-object v10, p1

    .line 42
    check-cast v10, Ll2/o;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    iget p1, p0, Lb71/g;->g:I

    .line 50
    .line 51
    or-int/lit8 p1, p1, 0x1

    .line 52
    .line 53
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 54
    .line 55
    .line 56
    move-result v11

    .line 57
    iget-object v2, p0, Lb71/g;->e:Lx2/s;

    .line 58
    .line 59
    iget-boolean v3, p0, Lb71/g;->f:Z

    .line 60
    .line 61
    invoke-static/range {v1 .. v11}, Lh2/q9;->b(Lh2/u7;Lx2/s;ZLh2/u8;Li1/l;Li1/l;Lt2/b;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 62
    .line 63
    .line 64
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object p0

    .line 67
    :pswitch_0
    iget-object v0, p0, Lb71/g;->h:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v2, v0

    .line 70
    check-cast v2, Ljava/lang/String;

    .line 71
    .line 72
    iget-object v0, p0, Lb71/g;->i:Ljava/lang/Object;

    .line 73
    .line 74
    move-object v3, v0

    .line 75
    check-cast v3, Ljava/lang/String;

    .line 76
    .line 77
    iget-object v0, p0, Lb71/g;->j:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v4, v0

    .line 80
    check-cast v4, Ljava/lang/String;

    .line 81
    .line 82
    iget-object v0, p0, Lb71/g;->k:Ljava/lang/Object;

    .line 83
    .line 84
    move-object v5, v0

    .line 85
    check-cast v5, Ljava/lang/String;

    .line 86
    .line 87
    iget-object v0, p0, Lb71/g;->l:Ljava/lang/Object;

    .line 88
    .line 89
    move-object v7, v0

    .line 90
    check-cast v7, Ljava/lang/String;

    .line 91
    .line 92
    iget-object v0, p0, Lb71/g;->m:Llx0/e;

    .line 93
    .line 94
    move-object v8, v0

    .line 95
    check-cast v8, Lay0/a;

    .line 96
    .line 97
    iget-object v0, p0, Lb71/g;->n:Llx0/e;

    .line 98
    .line 99
    move-object v9, v0

    .line 100
    check-cast v9, Lay0/a;

    .line 101
    .line 102
    move-object v10, p1

    .line 103
    check-cast v10, Ll2/o;

    .line 104
    .line 105
    check-cast p2, Ljava/lang/Integer;

    .line 106
    .line 107
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    iget p1, p0, Lb71/g;->g:I

    .line 111
    .line 112
    or-int/lit8 p1, p1, 0x1

    .line 113
    .line 114
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 115
    .line 116
    .line 117
    move-result v11

    .line 118
    iget-object v1, p0, Lb71/g;->e:Lx2/s;

    .line 119
    .line 120
    iget-boolean v6, p0, Lb71/g;->f:Z

    .line 121
    .line 122
    invoke-static/range {v1 .. v11}, Lb71/a;->e(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    goto :goto_0

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.class public final synthetic Li91/h2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:J

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZJLjava/lang/String;II)V
    .locals 0

    .line 1
    iput p8, p0, Li91/h2;->d:I

    iput-object p1, p0, Li91/h2;->i:Ljava/lang/Object;

    iput-object p2, p0, Li91/h2;->j:Ljava/lang/Object;

    iput-boolean p3, p0, Li91/h2;->e:Z

    iput-wide p4, p0, Li91/h2;->f:J

    iput-object p6, p0, Li91/h2;->g:Ljava/lang/String;

    iput p7, p0, Li91/h2;->h:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ZLi3/c;JLx2/s;II)V
    .locals 0

    .line 2
    const/4 p7, 0x2

    iput p7, p0, Li91/h2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/h2;->g:Ljava/lang/String;

    iput-boolean p2, p0, Li91/h2;->e:Z

    iput-object p3, p0, Li91/h2;->i:Ljava/lang/Object;

    iput-wide p4, p0, Li91/h2;->f:J

    iput-object p6, p0, Li91/h2;->j:Ljava/lang/Object;

    iput p8, p0, Li91/h2;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Li91/h2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/h2;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v3, v0

    .line 9
    check-cast v3, Li3/c;

    .line 10
    .line 11
    iget-object v0, p0, Li91/h2;->j:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v6, v0

    .line 14
    check-cast v6, Lx2/s;

    .line 15
    .line 16
    move-object v7, p1

    .line 17
    check-cast v7, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/4 p1, 0x1

    .line 25
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result v8

    .line 29
    iget-object v1, p0, Li91/h2;->g:Ljava/lang/String;

    .line 30
    .line 31
    iget-boolean v2, p0, Li91/h2;->e:Z

    .line 32
    .line 33
    iget-wide v4, p0, Li91/h2;->f:J

    .line 34
    .line 35
    iget v9, p0, Li91/h2;->h:I

    .line 36
    .line 37
    invoke-static/range {v1 .. v9}, Lxj/k;->i(Ljava/lang/String;ZLi3/c;JLx2/s;Ll2/o;II)V

    .line 38
    .line 39
    .line 40
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_0
    iget-object v0, p0, Li91/h2;->i:Ljava/lang/Object;

    .line 44
    .line 45
    move-object v1, v0

    .line 46
    check-cast v1, Li91/t2;

    .line 47
    .line 48
    iget-object v0, p0, Li91/h2;->j:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v2, v0

    .line 51
    check-cast v2, Li91/x1;

    .line 52
    .line 53
    move-object v7, p1

    .line 54
    check-cast v7, Ll2/o;

    .line 55
    .line 56
    check-cast p2, Ljava/lang/Integer;

    .line 57
    .line 58
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 59
    .line 60
    .line 61
    iget p1, p0, Li91/h2;->h:I

    .line 62
    .line 63
    or-int/lit8 p1, p1, 0x1

    .line 64
    .line 65
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    iget-boolean v3, p0, Li91/h2;->e:Z

    .line 70
    .line 71
    iget-wide v4, p0, Li91/h2;->f:J

    .line 72
    .line 73
    iget-object v6, p0, Li91/h2;->g:Ljava/lang/String;

    .line 74
    .line 75
    invoke-virtual/range {v1 .. v8}, Li91/t2;->a(Li91/x1;ZJLjava/lang/String;Ll2/o;I)V

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :pswitch_1
    iget-object v0, p0, Li91/h2;->i:Ljava/lang/Object;

    .line 80
    .line 81
    move-object v1, v0

    .line 82
    check-cast v1, Li91/k2;

    .line 83
    .line 84
    iget-object v0, p0, Li91/h2;->j:Ljava/lang/Object;

    .line 85
    .line 86
    move-object v2, v0

    .line 87
    check-cast v2, Li91/v1;

    .line 88
    .line 89
    move-object v7, p1

    .line 90
    check-cast v7, Ll2/o;

    .line 91
    .line 92
    check-cast p2, Ljava/lang/Integer;

    .line 93
    .line 94
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    iget p1, p0, Li91/h2;->h:I

    .line 98
    .line 99
    or-int/lit8 p1, p1, 0x1

    .line 100
    .line 101
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 102
    .line 103
    .line 104
    move-result v8

    .line 105
    iget-boolean v3, p0, Li91/h2;->e:Z

    .line 106
    .line 107
    iget-wide v4, p0, Li91/h2;->f:J

    .line 108
    .line 109
    iget-object v6, p0, Li91/h2;->g:Ljava/lang/String;

    .line 110
    .line 111
    invoke-virtual/range {v1 .. v8}, Li91/k2;->c(Li91/v1;ZJLjava/lang/String;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_0

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

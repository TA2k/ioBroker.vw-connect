.class public final synthetic Li91/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:Lx2/s;

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;JJLi91/j1;Lx2/s;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li91/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/a;->e:Ljava/lang/String;

    iput-wide p2, p0, Li91/a;->f:J

    iput-wide p4, p0, Li91/a;->g:J

    iput-object p6, p0, Li91/a;->j:Ljava/lang/Object;

    iput-object p7, p0, Li91/a;->h:Lx2/s;

    iput p8, p0, Li91/a;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;JJLx2/s;Ljava/lang/String;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Li91/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/a;->e:Ljava/lang/String;

    iput-wide p2, p0, Li91/a;->f:J

    iput-wide p4, p0, Li91/a;->g:J

    iput-object p6, p0, Li91/a;->h:Lx2/s;

    iput-object p7, p0, Li91/a;->j:Ljava/lang/Object;

    iput p8, p0, Li91/a;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;JLg4/p0;JII)V
    .locals 0

    .line 3
    const/4 p9, 0x2

    iput p9, p0, Li91/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/a;->h:Lx2/s;

    iput-object p2, p0, Li91/a;->e:Ljava/lang/String;

    iput-wide p3, p0, Li91/a;->f:J

    iput-object p5, p0, Li91/a;->j:Ljava/lang/Object;

    iput-wide p6, p0, Li91/a;->g:J

    iput p8, p0, Li91/a;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Li91/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/a;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v5, v0

    .line 9
    check-cast v5, Lg4/p0;

    .line 10
    .line 11
    move-object v9, p1

    .line 12
    check-cast v9, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 p1, 0xd81

    .line 20
    .line 21
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v10

    .line 25
    iget-object v1, p0, Li91/a;->h:Lx2/s;

    .line 26
    .line 27
    iget-object v2, p0, Li91/a;->e:Ljava/lang/String;

    .line 28
    .line 29
    iget-wide v3, p0, Li91/a;->f:J

    .line 30
    .line 31
    iget-wide v6, p0, Li91/a;->g:J

    .line 32
    .line 33
    iget v8, p0, Li91/a;->i:I

    .line 34
    .line 35
    invoke-static/range {v1 .. v10}, Luz/g;->l(Lx2/s;Ljava/lang/String;JLg4/p0;JILl2/o;I)V

    .line 36
    .line 37
    .line 38
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    iget-object v0, p0, Li91/a;->j:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v6, v0

    .line 44
    check-cast v6, Li91/j1;

    .line 45
    .line 46
    move-object v8, p1

    .line 47
    check-cast v8, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 52
    .line 53
    .line 54
    iget p1, p0, Li91/a;->i:I

    .line 55
    .line 56
    or-int/lit8 p1, p1, 0x1

    .line 57
    .line 58
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 59
    .line 60
    .line 61
    move-result v9

    .line 62
    iget-object v1, p0, Li91/a;->e:Ljava/lang/String;

    .line 63
    .line 64
    iget-wide v2, p0, Li91/a;->f:J

    .line 65
    .line 66
    iget-wide v4, p0, Li91/a;->g:J

    .line 67
    .line 68
    iget-object v7, p0, Li91/a;->h:Lx2/s;

    .line 69
    .line 70
    invoke-static/range {v1 .. v9}, Li91/j0;->A(Ljava/lang/String;JJLi91/j1;Lx2/s;Ll2/o;I)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_1
    iget-object v0, p0, Li91/a;->j:Ljava/lang/Object;

    .line 75
    .line 76
    move-object v7, v0

    .line 77
    check-cast v7, Ljava/lang/String;

    .line 78
    .line 79
    move-object v8, p1

    .line 80
    check-cast v8, Ll2/o;

    .line 81
    .line 82
    check-cast p2, Ljava/lang/Integer;

    .line 83
    .line 84
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    iget p1, p0, Li91/a;->i:I

    .line 88
    .line 89
    or-int/lit8 p1, p1, 0x1

    .line 90
    .line 91
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    iget-object v1, p0, Li91/a;->e:Ljava/lang/String;

    .line 96
    .line 97
    iget-wide v2, p0, Li91/a;->f:J

    .line 98
    .line 99
    iget-wide v4, p0, Li91/a;->g:J

    .line 100
    .line 101
    iget-object v6, p0, Li91/a;->h:Lx2/s;

    .line 102
    .line 103
    invoke-static/range {v1 .. v9}, Li91/j0;->h(Ljava/lang/String;JJLx2/s;Ljava/lang/String;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

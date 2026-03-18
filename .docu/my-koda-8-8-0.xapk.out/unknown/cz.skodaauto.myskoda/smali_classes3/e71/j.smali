.class public final synthetic Le71/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;II)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Le71/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le71/j;->e:Lay0/a;

    iput-object p2, p0, Le71/j;->f:Lx2/s;

    iput-boolean p3, p0, Le71/j;->g:Z

    iput-object p4, p0, Le71/j;->j:Ljava/lang/Object;

    iput-object p5, p0, Le71/j;->k:Ljava/lang/Object;

    iput-object p6, p0, Le71/j;->l:Ljava/lang/Object;

    iput p7, p0, Le71/j;->h:I

    iput p8, p0, Le71/j;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;ZLh71/w;Le71/a;Lay0/a;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Le71/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le71/j;->f:Lx2/s;

    iput-object p2, p0, Le71/j;->j:Ljava/lang/Object;

    iput-boolean p3, p0, Le71/j;->g:Z

    iput-object p4, p0, Le71/j;->k:Ljava/lang/Object;

    iput-object p5, p0, Le71/j;->l:Ljava/lang/Object;

    iput-object p6, p0, Le71/j;->e:Lay0/a;

    iput p7, p0, Le71/j;->h:I

    iput p8, p0, Le71/j;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Le71/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le71/j;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v4, v0

    .line 9
    check-cast v4, Lh2/d5;

    .line 10
    .line 11
    iget-object v0, p0, Le71/j;->k:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v5, v0

    .line 14
    check-cast v5, Le3/n0;

    .line 15
    .line 16
    iget-object v0, p0, Le71/j;->l:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v6, v0

    .line 19
    check-cast v6, Lay0/n;

    .line 20
    .line 21
    move-object v7, p1

    .line 22
    check-cast v7, Ll2/o;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget p1, p0, Le71/j;->h:I

    .line 30
    .line 31
    or-int/lit8 p1, p1, 0x1

    .line 32
    .line 33
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 34
    .line 35
    .line 36
    move-result v8

    .line 37
    iget-object v1, p0, Le71/j;->e:Lay0/a;

    .line 38
    .line 39
    iget-object v2, p0, Le71/j;->f:Lx2/s;

    .line 40
    .line 41
    iget-boolean v3, p0, Le71/j;->g:Z

    .line 42
    .line 43
    iget v9, p0, Le71/j;->i:I

    .line 44
    .line 45
    invoke-static/range {v1 .. v9}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 46
    .line 47
    .line 48
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    iget-object v0, p0, Le71/j;->j:Ljava/lang/Object;

    .line 52
    .line 53
    move-object v2, v0

    .line 54
    check-cast v2, Ljava/lang/String;

    .line 55
    .line 56
    iget-object v0, p0, Le71/j;->k:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v4, v0

    .line 59
    check-cast v4, Lh71/w;

    .line 60
    .line 61
    iget-object v0, p0, Le71/j;->l:Ljava/lang/Object;

    .line 62
    .line 63
    move-object v5, v0

    .line 64
    check-cast v5, Le71/a;

    .line 65
    .line 66
    move-object v7, p1

    .line 67
    check-cast v7, Ll2/o;

    .line 68
    .line 69
    check-cast p2, Ljava/lang/Integer;

    .line 70
    .line 71
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    iget p1, p0, Le71/j;->h:I

    .line 75
    .line 76
    or-int/lit8 p1, p1, 0x1

    .line 77
    .line 78
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 79
    .line 80
    .line 81
    move-result v8

    .line 82
    iget-object v1, p0, Le71/j;->f:Lx2/s;

    .line 83
    .line 84
    iget-boolean v3, p0, Le71/j;->g:Z

    .line 85
    .line 86
    iget-object v6, p0, Le71/j;->e:Lay0/a;

    .line 87
    .line 88
    iget v9, p0, Le71/j;->i:I

    .line 89
    .line 90
    invoke-static/range {v1 .. v9}, Lkp/h0;->a(Lx2/s;Ljava/lang/String;ZLh71/w;Le71/a;Lay0/a;Ll2/o;II)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    nop

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

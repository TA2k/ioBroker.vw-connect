.class public final synthetic Li91/x3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:I

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ZLay0/a;Lay0/k;Lx2/s;ZII)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li91/x3;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/x3;->f:Ljava/lang/String;

    iput-boolean p2, p0, Li91/x3;->g:Z

    iput-object p3, p0, Li91/x3;->j:Lay0/a;

    iput-object p4, p0, Li91/x3;->i:Lay0/k;

    iput-object p5, p0, Li91/x3;->e:Lx2/s;

    iput-boolean p6, p0, Li91/x3;->h:Z

    iput p7, p0, Li91/x3;->k:I

    iput p8, p0, Li91/x3;->l:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;ZZLay0/k;Lay0/a;II)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li91/x3;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/x3;->e:Lx2/s;

    iput-object p2, p0, Li91/x3;->f:Ljava/lang/String;

    iput-boolean p3, p0, Li91/x3;->g:Z

    iput-boolean p4, p0, Li91/x3;->h:Z

    iput-object p5, p0, Li91/x3;->i:Lay0/k;

    iput-object p6, p0, Li91/x3;->j:Lay0/a;

    iput p7, p0, Li91/x3;->k:I

    iput p8, p0, Li91/x3;->l:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Li91/x3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Li91/x3;->k:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget v2, p0, Li91/x3;->l:I

    .line 23
    .line 24
    iget-object v3, p0, Li91/x3;->j:Lay0/a;

    .line 25
    .line 26
    iget-object v4, p0, Li91/x3;->i:Lay0/k;

    .line 27
    .line 28
    iget-object v5, p0, Li91/x3;->f:Ljava/lang/String;

    .line 29
    .line 30
    iget-object v7, p0, Li91/x3;->e:Lx2/s;

    .line 31
    .line 32
    iget-boolean v8, p0, Li91/x3;->g:Z

    .line 33
    .line 34
    iget-boolean v9, p0, Li91/x3;->h:Z

    .line 35
    .line 36
    invoke-static/range {v1 .. v9}, Llp/se;->g(IILay0/a;Lay0/k;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 37
    .line 38
    .line 39
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    move-object v5, p1

    .line 43
    check-cast v5, Ll2/o;

    .line 44
    .line 45
    check-cast p2, Ljava/lang/Integer;

    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    iget p1, p0, Li91/x3;->k:I

    .line 51
    .line 52
    or-int/lit8 p1, p1, 0x1

    .line 53
    .line 54
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget v1, p0, Li91/x3;->l:I

    .line 59
    .line 60
    iget-object v2, p0, Li91/x3;->j:Lay0/a;

    .line 61
    .line 62
    iget-object v3, p0, Li91/x3;->i:Lay0/k;

    .line 63
    .line 64
    iget-object v4, p0, Li91/x3;->f:Ljava/lang/String;

    .line 65
    .line 66
    iget-object v6, p0, Li91/x3;->e:Lx2/s;

    .line 67
    .line 68
    iget-boolean v7, p0, Li91/x3;->g:Z

    .line 69
    .line 70
    iget-boolean v8, p0, Li91/x3;->h:Z

    .line 71
    .line 72
    invoke-static/range {v0 .. v8}, Li91/y3;->a(IILay0/a;Lay0/k;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

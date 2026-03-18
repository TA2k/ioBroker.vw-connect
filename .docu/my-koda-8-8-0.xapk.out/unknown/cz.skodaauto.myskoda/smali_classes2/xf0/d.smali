.class public final synthetic Lxf0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Landroid/net/Uri;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Landroid/graphics/Bitmap;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lt3/k;

.field public final synthetic k:Ljava/util/List;

.field public final synthetic l:Lay0/n;

.field public final synthetic m:Lay0/n;

.field public final synthetic n:I

.field public final synthetic o:I

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/d;->d:Landroid/net/Uri;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/d;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/d;->f:Landroid/graphics/Bitmap;

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/d;->g:Lay0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/d;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lxf0/d;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Lxf0/d;->j:Lt3/k;

    .line 17
    .line 18
    iput-object p8, p0, Lxf0/d;->k:Ljava/util/List;

    .line 19
    .line 20
    iput-object p9, p0, Lxf0/d;->l:Lay0/n;

    .line 21
    .line 22
    iput-object p10, p0, Lxf0/d;->m:Lay0/n;

    .line 23
    .line 24
    iput p11, p0, Lxf0/d;->n:I

    .line 25
    .line 26
    iput p12, p0, Lxf0/d;->o:I

    .line 27
    .line 28
    iput p13, p0, Lxf0/d;->p:I

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v6, Lx2/c;->h:Lx2/j;

    .line 4
    .line 5
    move-object/from16 v11, p1

    .line 6
    .line 7
    check-cast v11, Ll2/o;

    .line 8
    .line 9
    move-object/from16 v1, p2

    .line 10
    .line 11
    check-cast v1, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    iget v1, v0, Lxf0/d;->n:I

    .line 17
    .line 18
    or-int/lit8 v1, v1, 0x1

    .line 19
    .line 20
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v12

    .line 24
    iget v1, v0, Lxf0/d;->o:I

    .line 25
    .line 26
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 27
    .line 28
    .line 29
    move-result v13

    .line 30
    iget-object v1, v0, Lxf0/d;->d:Landroid/net/Uri;

    .line 31
    .line 32
    move-object v2, v1

    .line 33
    iget-object v1, v0, Lxf0/d;->e:Lx2/s;

    .line 34
    .line 35
    move-object v3, v2

    .line 36
    iget-object v2, v0, Lxf0/d;->f:Landroid/graphics/Bitmap;

    .line 37
    .line 38
    move-object v4, v3

    .line 39
    iget-object v3, v0, Lxf0/d;->g:Lay0/a;

    .line 40
    .line 41
    move-object v5, v4

    .line 42
    iget-object v4, v0, Lxf0/d;->h:Lay0/a;

    .line 43
    .line 44
    move-object v7, v5

    .line 45
    iget-object v5, v0, Lxf0/d;->i:Lay0/a;

    .line 46
    .line 47
    move-object v8, v7

    .line 48
    iget-object v7, v0, Lxf0/d;->j:Lt3/k;

    .line 49
    .line 50
    move-object v9, v8

    .line 51
    iget-object v8, v0, Lxf0/d;->k:Ljava/util/List;

    .line 52
    .line 53
    move-object v10, v9

    .line 54
    iget-object v9, v0, Lxf0/d;->l:Lay0/n;

    .line 55
    .line 56
    move-object v14, v10

    .line 57
    iget-object v10, v0, Lxf0/d;->m:Lay0/n;

    .line 58
    .line 59
    iget v0, v0, Lxf0/d;->p:I

    .line 60
    .line 61
    move-object v15, v14

    .line 62
    move v14, v0

    .line 63
    move-object v0, v15

    .line 64
    invoke-static/range {v0 .. v14}, Lxf0/i0;->F(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lx2/e;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;Ll2/o;III)V

    .line 65
    .line 66
    .line 67
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object v0
.end method

.class public final synthetic Li91/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lg4/g;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Lg4/g;

.field public final synthetic j:I

.field public final synthetic k:I

.field public final synthetic l:Lay0/o;

.field public final synthetic m:Li91/w3;

.field public final synthetic n:Lay0/o;

.field public final synthetic o:I

.field public final synthetic p:I

.field public final synthetic q:I


# direct methods
.method public synthetic constructor <init>(Lg4/g;Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg4/g;IILay0/o;Li91/w3;Lay0/o;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/u0;->d:Lg4/g;

    .line 5
    .line 6
    iput-object p2, p0, Li91/u0;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Li91/u0;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Li91/u0;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Li91/u0;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Li91/u0;->i:Lg4/g;

    .line 15
    .line 16
    iput p7, p0, Li91/u0;->j:I

    .line 17
    .line 18
    iput p8, p0, Li91/u0;->k:I

    .line 19
    .line 20
    iput-object p9, p0, Li91/u0;->l:Lay0/o;

    .line 21
    .line 22
    iput-object p10, p0, Li91/u0;->m:Li91/w3;

    .line 23
    .line 24
    iput-object p11, p0, Li91/u0;->n:Lay0/o;

    .line 25
    .line 26
    iput p12, p0, Li91/u0;->o:I

    .line 27
    .line 28
    iput p13, p0, Li91/u0;->p:I

    .line 29
    .line 30
    iput p14, p0, Li91/u0;->q:I

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v11, p1

    .line 4
    .line 5
    check-cast v11, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget v1, v0, Li91/u0;->o:I

    .line 15
    .line 16
    or-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v12

    .line 22
    iget v1, v0, Li91/u0;->p:I

    .line 23
    .line 24
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result v13

    .line 28
    iget-object v1, v0, Li91/u0;->d:Lg4/g;

    .line 29
    .line 30
    move-object v2, v1

    .line 31
    iget-object v1, v0, Li91/u0;->e:Lx2/s;

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    iget-object v2, v0, Li91/u0;->f:Ljava/lang/String;

    .line 35
    .line 36
    move-object v4, v3

    .line 37
    iget-object v3, v0, Li91/u0;->g:Ljava/lang/String;

    .line 38
    .line 39
    move-object v5, v4

    .line 40
    iget-object v4, v0, Li91/u0;->h:Ljava/lang/String;

    .line 41
    .line 42
    move-object v6, v5

    .line 43
    iget-object v5, v0, Li91/u0;->i:Lg4/g;

    .line 44
    .line 45
    move-object v7, v6

    .line 46
    iget v6, v0, Li91/u0;->j:I

    .line 47
    .line 48
    move-object v8, v7

    .line 49
    iget v7, v0, Li91/u0;->k:I

    .line 50
    .line 51
    move-object v9, v8

    .line 52
    iget-object v8, v0, Li91/u0;->l:Lay0/o;

    .line 53
    .line 54
    move-object v10, v9

    .line 55
    iget-object v9, v0, Li91/u0;->m:Li91/w3;

    .line 56
    .line 57
    move-object v14, v10

    .line 58
    iget-object v10, v0, Li91/u0;->n:Lay0/o;

    .line 59
    .line 60
    iget v0, v0, Li91/u0;->q:I

    .line 61
    .line 62
    move-object v15, v14

    .line 63
    move v14, v0

    .line 64
    move-object v0, v15

    .line 65
    invoke-static/range {v0 .. v14}, Li91/j0;->j(Lg4/g;Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg4/g;IILay0/o;Li91/w3;Lay0/o;Ll2/o;III)V

    .line 66
    .line 67
    .line 68
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    return-object v0
.end method

.class public final synthetic Lc71/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Z

.field public final synthetic i:Z

.field public final synthetic j:Lay0/o;

.field public final synthetic k:Lay0/o;

.field public final synthetic l:Lk1/i;

.field public final synthetic m:Lx2/d;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:I

.field public final synthetic p:I

.field public final synthetic q:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;ZLjava/lang/String;ZZLay0/o;Lay0/o;Lk1/i;Lx2/d;Lay0/a;III)V
    .locals 1

    .line 1
    sget-object v0, Lh71/a;->d:Lh71/a;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lc71/f;->d:Lx2/s;

    .line 7
    .line 8
    iput-object p2, p0, Lc71/f;->e:Ljava/lang/String;

    .line 9
    .line 10
    iput-boolean p3, p0, Lc71/f;->f:Z

    .line 11
    .line 12
    iput-object p4, p0, Lc71/f;->g:Ljava/lang/String;

    .line 13
    .line 14
    iput-boolean p5, p0, Lc71/f;->h:Z

    .line 15
    .line 16
    iput-boolean p6, p0, Lc71/f;->i:Z

    .line 17
    .line 18
    iput-object p7, p0, Lc71/f;->j:Lay0/o;

    .line 19
    .line 20
    iput-object p8, p0, Lc71/f;->k:Lay0/o;

    .line 21
    .line 22
    iput-object p9, p0, Lc71/f;->l:Lk1/i;

    .line 23
    .line 24
    iput-object p10, p0, Lc71/f;->m:Lx2/d;

    .line 25
    .line 26
    iput-object p11, p0, Lc71/f;->n:Lay0/a;

    .line 27
    .line 28
    iput p12, p0, Lc71/f;->o:I

    .line 29
    .line 30
    iput p13, p0, Lc71/f;->p:I

    .line 31
    .line 32
    iput p14, p0, Lc71/f;->q:I

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lh71/a;->d:Lh71/a;

    .line 4
    .line 5
    move-object/from16 v13, p1

    .line 6
    .line 7
    check-cast v13, Ll2/o;

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
    iget v1, v0, Lc71/f;->o:I

    .line 17
    .line 18
    or-int/lit8 v1, v1, 0x1

    .line 19
    .line 20
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v14

    .line 24
    iget v1, v0, Lc71/f;->p:I

    .line 25
    .line 26
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 27
    .line 28
    .line 29
    move-result v15

    .line 30
    iget-object v2, v0, Lc71/f;->d:Lx2/s;

    .line 31
    .line 32
    iget-object v3, v0, Lc71/f;->e:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean v4, v0, Lc71/f;->f:Z

    .line 35
    .line 36
    iget-object v5, v0, Lc71/f;->g:Ljava/lang/String;

    .line 37
    .line 38
    iget-boolean v6, v0, Lc71/f;->h:Z

    .line 39
    .line 40
    iget-boolean v7, v0, Lc71/f;->i:Z

    .line 41
    .line 42
    iget-object v8, v0, Lc71/f;->j:Lay0/o;

    .line 43
    .line 44
    iget-object v9, v0, Lc71/f;->k:Lay0/o;

    .line 45
    .line 46
    iget-object v10, v0, Lc71/f;->l:Lk1/i;

    .line 47
    .line 48
    iget-object v11, v0, Lc71/f;->m:Lx2/d;

    .line 49
    .line 50
    iget-object v12, v0, Lc71/f;->n:Lay0/a;

    .line 51
    .line 52
    iget v0, v0, Lc71/f;->q:I

    .line 53
    .line 54
    move/from16 v16, v0

    .line 55
    .line 56
    invoke-static/range {v2 .. v16}, Lc71/a;->b(Lx2/s;Ljava/lang/String;ZLjava/lang/String;ZZLay0/o;Lay0/o;Lk1/i;Lx2/d;Lay0/a;Ll2/o;III)V

    .line 57
    .line 58
    .line 59
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object v0
.end method

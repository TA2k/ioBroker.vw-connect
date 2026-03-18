.class public final synthetic Li91/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Li91/x1;

.field public final synthetic h:Li91/v1;

.field public final synthetic i:Z

.field public final synthetic j:Li91/t1;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:F

.field public final synthetic m:Ljava/lang/String;

.field public final synthetic n:I

.field public final synthetic o:I

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/t0;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Li91/t0;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Li91/t0;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Li91/t0;->g:Li91/x1;

    .line 11
    .line 12
    iput-object p5, p0, Li91/t0;->h:Li91/v1;

    .line 13
    .line 14
    iput-boolean p6, p0, Li91/t0;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Li91/t0;->j:Li91/t1;

    .line 17
    .line 18
    iput-object p8, p0, Li91/t0;->k:Lay0/a;

    .line 19
    .line 20
    iput p9, p0, Li91/t0;->l:F

    .line 21
    .line 22
    iput-object p10, p0, Li91/t0;->m:Ljava/lang/String;

    .line 23
    .line 24
    iput p11, p0, Li91/t0;->n:I

    .line 25
    .line 26
    iput p12, p0, Li91/t0;->o:I

    .line 27
    .line 28
    iput p13, p0, Li91/t0;->p:I

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    move-object/from16 v0, p2

    .line 5
    .line 6
    check-cast v0, Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget v0, p0, Li91/t0;->n:I

    .line 12
    .line 13
    or-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v11

    .line 19
    iget v0, p0, Li91/t0;->o:I

    .line 20
    .line 21
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v12

    .line 25
    iget-object v0, p0, Li91/t0;->d:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v1, p0, Li91/t0;->e:Lx2/s;

    .line 28
    .line 29
    iget-object v2, p0, Li91/t0;->f:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v3, p0, Li91/t0;->g:Li91/x1;

    .line 32
    .line 33
    iget-object v4, p0, Li91/t0;->h:Li91/v1;

    .line 34
    .line 35
    iget-boolean v5, p0, Li91/t0;->i:Z

    .line 36
    .line 37
    iget-object v6, p0, Li91/t0;->j:Li91/t1;

    .line 38
    .line 39
    iget-object v7, p0, Li91/t0;->k:Lay0/a;

    .line 40
    .line 41
    iget v8, p0, Li91/t0;->l:F

    .line 42
    .line 43
    iget-object v9, p0, Li91/t0;->m:Ljava/lang/String;

    .line 44
    .line 45
    iget v13, p0, Li91/t0;->p:I

    .line 46
    .line 47
    invoke-static/range {v0 .. v13}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 48
    .line 49
    .line 50
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0
.end method

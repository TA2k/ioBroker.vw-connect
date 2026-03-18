.class public final synthetic Luu/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Luu/l1;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:F

.field public final synthetic g:J

.field public final synthetic h:Lsp/b;

.field public final synthetic i:J

.field public final synthetic j:Z

.field public final synthetic k:F

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Luu/l1;Ljava/lang/String;FJLsp/b;JZFLay0/k;Lay0/k;Lay0/k;Lay0/k;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/j1;->d:Luu/l1;

    .line 5
    .line 6
    iput-object p2, p0, Luu/j1;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput p3, p0, Luu/j1;->f:F

    .line 9
    .line 10
    iput-wide p4, p0, Luu/j1;->g:J

    .line 11
    .line 12
    iput-object p6, p0, Luu/j1;->h:Lsp/b;

    .line 13
    .line 14
    iput-wide p7, p0, Luu/j1;->i:J

    .line 15
    .line 16
    iput-boolean p9, p0, Luu/j1;->j:Z

    .line 17
    .line 18
    iput p10, p0, Luu/j1;->k:F

    .line 19
    .line 20
    iput-object p11, p0, Luu/j1;->l:Lay0/k;

    .line 21
    .line 22
    iput-object p12, p0, Luu/j1;->m:Lay0/k;

    .line 23
    .line 24
    iput-object p13, p0, Luu/j1;->n:Lay0/k;

    .line 25
    .line 26
    iput-object p14, p0, Luu/j1;->o:Lay0/k;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v14, p1

    .line 4
    .line 5
    check-cast v14, Ll2/o;

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
    const/4 v1, 0x1

    .line 15
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v15

    .line 19
    iget-object v1, v0, Luu/j1;->d:Luu/l1;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    iget-object v1, v0, Luu/j1;->e:Ljava/lang/String;

    .line 23
    .line 24
    move-object v3, v2

    .line 25
    iget v2, v0, Luu/j1;->f:F

    .line 26
    .line 27
    move-object v5, v3

    .line 28
    iget-wide v3, v0, Luu/j1;->g:J

    .line 29
    .line 30
    move-object v6, v5

    .line 31
    iget-object v5, v0, Luu/j1;->h:Lsp/b;

    .line 32
    .line 33
    move-object v8, v6

    .line 34
    iget-wide v6, v0, Luu/j1;->i:J

    .line 35
    .line 36
    move-object v9, v8

    .line 37
    iget-boolean v8, v0, Luu/j1;->j:Z

    .line 38
    .line 39
    move-object v10, v9

    .line 40
    iget v9, v0, Luu/j1;->k:F

    .line 41
    .line 42
    move-object v11, v10

    .line 43
    iget-object v10, v0, Luu/j1;->l:Lay0/k;

    .line 44
    .line 45
    move-object v12, v11

    .line 46
    iget-object v11, v0, Luu/j1;->m:Lay0/k;

    .line 47
    .line 48
    move-object v13, v12

    .line 49
    iget-object v12, v0, Luu/j1;->n:Lay0/k;

    .line 50
    .line 51
    iget-object v0, v0, Luu/j1;->o:Lay0/k;

    .line 52
    .line 53
    move-object/from16 v16, v13

    .line 54
    .line 55
    move-object v13, v0

    .line 56
    move-object/from16 v0, v16

    .line 57
    .line 58
    invoke-static/range {v0 .. v15}, Llp/ia;->a(Luu/l1;Ljava/lang/String;FJLsp/b;JZFLay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 59
    .line 60
    .line 61
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    return-object v0
.end method

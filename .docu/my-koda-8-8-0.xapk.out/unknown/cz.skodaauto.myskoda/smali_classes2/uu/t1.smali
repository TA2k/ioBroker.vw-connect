.class public final synthetic Luu/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/util/ArrayList;

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:J

.field public final synthetic g:Lsp/d;

.field public final synthetic h:Ljava/util/List;

.field public final synthetic i:Lsp/d;

.field public final synthetic j:Z

.field public final synthetic k:F

.field public final synthetic l:Lay0/k;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Ljava/util/List;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/t1;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput-object p2, p0, Luu/t1;->e:Ljava/util/List;

    .line 7
    .line 8
    iput-wide p3, p0, Luu/t1;->f:J

    .line 9
    .line 10
    iput-object p5, p0, Luu/t1;->g:Lsp/d;

    .line 11
    .line 12
    iput-object p6, p0, Luu/t1;->h:Ljava/util/List;

    .line 13
    .line 14
    iput-object p7, p0, Luu/t1;->i:Lsp/d;

    .line 15
    .line 16
    iput-boolean p8, p0, Luu/t1;->j:Z

    .line 17
    .line 18
    iput p9, p0, Luu/t1;->k:F

    .line 19
    .line 20
    iput-object p10, p0, Luu/t1;->l:Lay0/k;

    .line 21
    .line 22
    iput p11, p0, Luu/t1;->m:I

    .line 23
    .line 24
    iput p12, p0, Luu/t1;->n:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Luu/t1;->m:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v11

    .line 17
    iget p1, p0, Luu/t1;->n:I

    .line 18
    .line 19
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 20
    .line 21
    .line 22
    move-result v12

    .line 23
    iget-object v0, p0, Luu/t1;->d:Ljava/util/ArrayList;

    .line 24
    .line 25
    iget-object v1, p0, Luu/t1;->e:Ljava/util/List;

    .line 26
    .line 27
    iget-wide v2, p0, Luu/t1;->f:J

    .line 28
    .line 29
    iget-object v4, p0, Luu/t1;->g:Lsp/d;

    .line 30
    .line 31
    iget-object v5, p0, Luu/t1;->h:Ljava/util/List;

    .line 32
    .line 33
    iget-object v6, p0, Luu/t1;->i:Lsp/d;

    .line 34
    .line 35
    iget-boolean v7, p0, Luu/t1;->j:Z

    .line 36
    .line 37
    iget v8, p0, Luu/t1;->k:F

    .line 38
    .line 39
    iget-object v9, p0, Luu/t1;->l:Lay0/k;

    .line 40
    .line 41
    invoke-static/range {v0 .. v12}, Llp/ka;->b(Ljava/util/ArrayList;Ljava/util/List;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;Ll2/o;II)V

    .line 42
    .line 43
    .line 44
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0
.end method

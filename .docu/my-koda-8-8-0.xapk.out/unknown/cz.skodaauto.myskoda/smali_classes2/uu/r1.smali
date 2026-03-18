.class public final synthetic Luu/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/util/ArrayList;

.field public final synthetic e:J

.field public final synthetic f:Lsp/d;

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:Lsp/d;

.field public final synthetic i:Z

.field public final synthetic j:F

.field public final synthetic k:Lay0/k;

.field public final synthetic l:I

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/r1;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput-wide p2, p0, Luu/r1;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Luu/r1;->f:Lsp/d;

    .line 9
    .line 10
    iput-object p5, p0, Luu/r1;->g:Ljava/util/List;

    .line 11
    .line 12
    iput-object p6, p0, Luu/r1;->h:Lsp/d;

    .line 13
    .line 14
    iput-boolean p7, p0, Luu/r1;->i:Z

    .line 15
    .line 16
    iput p8, p0, Luu/r1;->j:F

    .line 17
    .line 18
    iput-object p9, p0, Luu/r1;->k:Lay0/k;

    .line 19
    .line 20
    iput p11, p0, Luu/r1;->l:I

    .line 21
    .line 22
    iput p12, p0, Luu/r1;->m:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object v9, p1

    .line 2
    check-cast v9, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v10

    .line 14
    iget p1, p0, Luu/r1;->l:I

    .line 15
    .line 16
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 17
    .line 18
    .line 19
    move-result v11

    .line 20
    iget-object v0, p0, Luu/r1;->d:Ljava/util/ArrayList;

    .line 21
    .line 22
    iget-wide v1, p0, Luu/r1;->e:J

    .line 23
    .line 24
    iget-object v3, p0, Luu/r1;->f:Lsp/d;

    .line 25
    .line 26
    iget-object v4, p0, Luu/r1;->g:Ljava/util/List;

    .line 27
    .line 28
    iget-object v5, p0, Luu/r1;->h:Lsp/d;

    .line 29
    .line 30
    iget-boolean v6, p0, Luu/r1;->i:Z

    .line 31
    .line 32
    iget v7, p0, Luu/r1;->j:F

    .line 33
    .line 34
    iget-object v8, p0, Luu/r1;->k:Lay0/k;

    .line 35
    .line 36
    iget v12, p0, Luu/r1;->m:I

    .line 37
    .line 38
    invoke-static/range {v0 .. v12}, Llp/ka;->a(Ljava/util/ArrayList;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;Ll2/o;III)V

    .line 39
    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0
.end method

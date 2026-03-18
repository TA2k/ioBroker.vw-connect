.class public final synthetic Lxf0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:I

.field public final synthetic g:F

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:Ljava/util/List;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Z

.field public final synthetic l:Z


# direct methods
.method public synthetic constructor <init>(ILjava/util/List;IFLjava/lang/Integer;Ljava/util/List;Lay0/k;ZZI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/v;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/v;->e:Ljava/util/List;

    .line 7
    .line 8
    iput p3, p0, Lxf0/v;->f:I

    .line 9
    .line 10
    iput p4, p0, Lxf0/v;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/v;->h:Ljava/lang/Integer;

    .line 13
    .line 14
    iput-object p6, p0, Lxf0/v;->i:Ljava/util/List;

    .line 15
    .line 16
    iput-object p7, p0, Lxf0/v;->j:Lay0/k;

    .line 17
    .line 18
    iput-boolean p8, p0, Lxf0/v;->k:Z

    .line 19
    .line 20
    iput-boolean p9, p0, Lxf0/v;->l:Z

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

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
    const/4 p1, 0x7

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v10

    .line 14
    iget v0, p0, Lxf0/v;->d:I

    .line 15
    .line 16
    iget-object v1, p0, Lxf0/v;->e:Ljava/util/List;

    .line 17
    .line 18
    iget v2, p0, Lxf0/v;->f:I

    .line 19
    .line 20
    iget v3, p0, Lxf0/v;->g:F

    .line 21
    .line 22
    iget-object v4, p0, Lxf0/v;->h:Ljava/lang/Integer;

    .line 23
    .line 24
    iget-object v5, p0, Lxf0/v;->i:Ljava/util/List;

    .line 25
    .line 26
    iget-object v6, p0, Lxf0/v;->j:Lay0/k;

    .line 27
    .line 28
    iget-boolean v7, p0, Lxf0/v;->k:Z

    .line 29
    .line 30
    iget-boolean v8, p0, Lxf0/v;->l:Z

    .line 31
    .line 32
    invoke-static/range {v0 .. v10}, Lxf0/b0;->a(ILjava/util/List;IFLjava/lang/Integer;Ljava/util/List;Lay0/k;ZZLl2/o;I)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0
.end method

.class public final synthetic Lxf0/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/util/List;

.field public final synthetic e:I

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:Z

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:I

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;ILay0/k;Lx2/s;ZZLjava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/c0;->d:Ljava/util/List;

    .line 5
    .line 6
    iput p2, p0, Lxf0/c0;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/c0;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/c0;->g:Lx2/s;

    .line 11
    .line 12
    iput-boolean p5, p0, Lxf0/c0;->h:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lxf0/c0;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Lxf0/c0;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput p8, p0, Lxf0/c0;->k:I

    .line 19
    .line 20
    iput p9, p0, Lxf0/c0;->l:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v7, p1

    .line 2
    check-cast v7, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lxf0/c0;->k:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v8

    .line 17
    iget-object v0, p0, Lxf0/c0;->d:Ljava/util/List;

    .line 18
    .line 19
    iget v1, p0, Lxf0/c0;->e:I

    .line 20
    .line 21
    iget-object v2, p0, Lxf0/c0;->f:Lay0/k;

    .line 22
    .line 23
    iget-object v3, p0, Lxf0/c0;->g:Lx2/s;

    .line 24
    .line 25
    iget-boolean v4, p0, Lxf0/c0;->h:Z

    .line 26
    .line 27
    iget-boolean v5, p0, Lxf0/c0;->i:Z

    .line 28
    .line 29
    iget-object v6, p0, Lxf0/c0;->j:Ljava/lang/String;

    .line 30
    .line 31
    iget v9, p0, Lxf0/c0;->l:I

    .line 32
    .line 33
    invoke-static/range {v0 .. v9}, Lxf0/i0;->g(Ljava/util/List;ILay0/k;Lx2/s;ZZLjava/lang/String;Ll2/o;II)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method

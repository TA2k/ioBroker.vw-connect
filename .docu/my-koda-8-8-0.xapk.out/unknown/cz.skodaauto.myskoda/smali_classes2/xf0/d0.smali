.class public final synthetic Lxf0/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Landroidx/datastore/preferences/protobuf/k;

.field public final synthetic i:Ljava/util/List;

.field public final synthetic j:F

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/n;

.field public final synthetic m:Lt2/b;

.field public final synthetic n:I

.field public final synthetic o:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ll2/b1;Lx2/s;Lay0/n;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;FLay0/a;Lay0/n;Lt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/d0;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/d0;->e:Ll2/b1;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/d0;->f:Lx2/s;

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/d0;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/d0;->h:Landroidx/datastore/preferences/protobuf/k;

    .line 13
    .line 14
    iput-object p6, p0, Lxf0/d0;->i:Ljava/util/List;

    .line 15
    .line 16
    iput p7, p0, Lxf0/d0;->j:F

    .line 17
    .line 18
    iput-object p8, p0, Lxf0/d0;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Lxf0/d0;->l:Lay0/n;

    .line 21
    .line 22
    iput-object p10, p0, Lxf0/d0;->m:Lt2/b;

    .line 23
    .line 24
    iput p11, p0, Lxf0/d0;->n:I

    .line 25
    .line 26
    iput p12, p0, Lxf0/d0;->o:I

    .line 27
    .line 28
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
    iget p1, p0, Lxf0/d0;->n:I

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
    iget-object v0, p0, Lxf0/d0;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Lxf0/d0;->e:Ll2/b1;

    .line 20
    .line 21
    iget-object v2, p0, Lxf0/d0;->f:Lx2/s;

    .line 22
    .line 23
    iget-object v3, p0, Lxf0/d0;->g:Lay0/n;

    .line 24
    .line 25
    iget-object v4, p0, Lxf0/d0;->h:Landroidx/datastore/preferences/protobuf/k;

    .line 26
    .line 27
    iget-object v5, p0, Lxf0/d0;->i:Ljava/util/List;

    .line 28
    .line 29
    iget v6, p0, Lxf0/d0;->j:F

    .line 30
    .line 31
    iget-object v7, p0, Lxf0/d0;->k:Lay0/a;

    .line 32
    .line 33
    iget-object v8, p0, Lxf0/d0;->l:Lay0/n;

    .line 34
    .line 35
    iget-object v9, p0, Lxf0/d0;->m:Lt2/b;

    .line 36
    .line 37
    iget v12, p0, Lxf0/d0;->o:I

    .line 38
    .line 39
    invoke-static/range {v0 .. v12}, Lxf0/f0;->b(Ljava/lang/String;Ll2/b1;Lx2/s;Lay0/n;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;FLay0/a;Lay0/n;Lt2/b;Ll2/o;II)V

    .line 40
    .line 41
    .line 42
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0
.end method

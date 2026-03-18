.class public final synthetic Lxf0/y2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Ljava/util/ArrayList;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:J

.field public final synthetic i:I

.field public final synthetic j:J

.field public final synthetic k:Ljava/lang/Float;

.field public final synthetic l:J

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/util/ArrayList;IIJIJLjava/lang/Float;JI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/y2;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/y2;->e:Ljava/util/ArrayList;

    .line 7
    .line 8
    iput p3, p0, Lxf0/y2;->f:I

    .line 9
    .line 10
    iput p4, p0, Lxf0/y2;->g:I

    .line 11
    .line 12
    iput-wide p5, p0, Lxf0/y2;->h:J

    .line 13
    .line 14
    iput p7, p0, Lxf0/y2;->i:I

    .line 15
    .line 16
    iput-wide p8, p0, Lxf0/y2;->j:J

    .line 17
    .line 18
    iput-object p10, p0, Lxf0/y2;->k:Ljava/lang/Float;

    .line 19
    .line 20
    iput-wide p11, p0, Lxf0/y2;->l:J

    .line 21
    .line 22
    iput p13, p0, Lxf0/y2;->m:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v12, p1

    .line 4
    .line 5
    check-cast v12, Ll2/o;

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
    iget v1, v0, Lxf0/y2;->m:I

    .line 15
    .line 16
    or-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v13

    .line 22
    iget-object v1, v0, Lxf0/y2;->d:Lx2/s;

    .line 23
    .line 24
    move-object v2, v1

    .line 25
    iget-object v1, v0, Lxf0/y2;->e:Ljava/util/ArrayList;

    .line 26
    .line 27
    move-object v3, v2

    .line 28
    iget v2, v0, Lxf0/y2;->f:I

    .line 29
    .line 30
    move-object v4, v3

    .line 31
    iget v3, v0, Lxf0/y2;->g:I

    .line 32
    .line 33
    move-object v6, v4

    .line 34
    iget-wide v4, v0, Lxf0/y2;->h:J

    .line 35
    .line 36
    move-object v7, v6

    .line 37
    iget v6, v0, Lxf0/y2;->i:I

    .line 38
    .line 39
    move-object v9, v7

    .line 40
    iget-wide v7, v0, Lxf0/y2;->j:J

    .line 41
    .line 42
    move-object v10, v9

    .line 43
    iget-object v9, v0, Lxf0/y2;->k:Ljava/lang/Float;

    .line 44
    .line 45
    iget-wide v14, v0, Lxf0/y2;->l:J

    .line 46
    .line 47
    move-object v0, v10

    .line 48
    move-wide v10, v14

    .line 49
    invoke-static/range {v0 .. v13}, Lxf0/z2;->b(Lx2/s;Ljava/util/ArrayList;IIJIJLjava/lang/Float;JLl2/o;I)V

    .line 50
    .line 51
    .line 52
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object v0
.end method

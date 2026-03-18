.class public final synthetic Lxf0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Z

.field public final synthetic i:J

.field public final synthetic j:Z

.field public final synthetic k:Z

.field public final synthetic l:Ljava/lang/Integer;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:I

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZLjava/lang/Integer;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/p;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/p;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/p;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/p;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-boolean p5, p0, Lxf0/p;->h:Z

    .line 13
    .line 14
    iput-wide p6, p0, Lxf0/p;->i:J

    .line 15
    .line 16
    iput-boolean p8, p0, Lxf0/p;->j:Z

    .line 17
    .line 18
    iput-boolean p9, p0, Lxf0/p;->k:Z

    .line 19
    .line 20
    iput-object p10, p0, Lxf0/p;->l:Ljava/lang/Integer;

    .line 21
    .line 22
    iput-object p11, p0, Lxf0/p;->m:Lay0/a;

    .line 23
    .line 24
    iput-object p12, p0, Lxf0/p;->n:Lay0/a;

    .line 25
    .line 26
    iput p13, p0, Lxf0/p;->o:I

    .line 27
    .line 28
    iput p14, p0, Lxf0/p;->p:I

    .line 29
    .line 30
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
    iget v1, v0, Lxf0/p;->o:I

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
    iget v1, v0, Lxf0/p;->p:I

    .line 23
    .line 24
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 25
    .line 26
    .line 27
    move-result v14

    .line 28
    iget-object v1, v0, Lxf0/p;->d:Ljava/lang/String;

    .line 29
    .line 30
    move-object v2, v1

    .line 31
    iget-object v1, v0, Lxf0/p;->e:Ljava/lang/String;

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    iget-object v2, v0, Lxf0/p;->f:Ljava/lang/String;

    .line 35
    .line 36
    move-object v4, v3

    .line 37
    iget-object v3, v0, Lxf0/p;->g:Ljava/lang/String;

    .line 38
    .line 39
    move-object v5, v4

    .line 40
    iget-boolean v4, v0, Lxf0/p;->h:Z

    .line 41
    .line 42
    move-object v7, v5

    .line 43
    iget-wide v5, v0, Lxf0/p;->i:J

    .line 44
    .line 45
    move-object v8, v7

    .line 46
    iget-boolean v7, v0, Lxf0/p;->j:Z

    .line 47
    .line 48
    move-object v9, v8

    .line 49
    iget-boolean v8, v0, Lxf0/p;->k:Z

    .line 50
    .line 51
    move-object v10, v9

    .line 52
    iget-object v9, v0, Lxf0/p;->l:Ljava/lang/Integer;

    .line 53
    .line 54
    move-object v11, v10

    .line 55
    iget-object v10, v0, Lxf0/p;->m:Lay0/a;

    .line 56
    .line 57
    iget-object v0, v0, Lxf0/p;->n:Lay0/a;

    .line 58
    .line 59
    move-object v15, v11

    .line 60
    move-object v11, v0

    .line 61
    move-object v0, v15

    .line 62
    invoke-static/range {v0 .. v14}, Lxf0/q;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZLjava/lang/Integer;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 63
    .line 64
    .line 65
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object v0
.end method

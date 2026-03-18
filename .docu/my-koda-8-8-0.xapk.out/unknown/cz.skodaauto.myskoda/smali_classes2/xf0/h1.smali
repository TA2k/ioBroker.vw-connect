.class public final synthetic Lxf0/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:I

.field public final synthetic l:Ljava/lang/Integer;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/a;ILjava/lang/Integer;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/h1;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/h1;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/h1;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/h1;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/h1;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lxf0/h1;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Lxf0/h1;->j:Lay0/a;

    .line 17
    .line 18
    iput p8, p0, Lxf0/h1;->k:I

    .line 19
    .line 20
    iput-object p9, p0, Lxf0/h1;->l:Ljava/lang/Integer;

    .line 21
    .line 22
    iput p10, p0, Lxf0/h1;->m:I

    .line 23
    .line 24
    iput p11, p0, Lxf0/h1;->n:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

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
    iget p1, p0, Lxf0/h1;->m:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v10

    .line 17
    iget-object v0, p0, Lxf0/h1;->d:Lx2/s;

    .line 18
    .line 19
    iget-object v1, p0, Lxf0/h1;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v2, p0, Lxf0/h1;->f:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v3, p0, Lxf0/h1;->g:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v4, p0, Lxf0/h1;->h:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v5, p0, Lxf0/h1;->i:Lay0/a;

    .line 28
    .line 29
    iget-object v6, p0, Lxf0/h1;->j:Lay0/a;

    .line 30
    .line 31
    iget v7, p0, Lxf0/h1;->k:I

    .line 32
    .line 33
    iget-object v8, p0, Lxf0/h1;->l:Ljava/lang/Integer;

    .line 34
    .line 35
    iget v11, p0, Lxf0/h1;->n:I

    .line 36
    .line 37
    invoke-static/range {v0 .. v11}, Lxf0/i0;->v(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/a;ILjava/lang/Integer;Ll2/o;II)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method

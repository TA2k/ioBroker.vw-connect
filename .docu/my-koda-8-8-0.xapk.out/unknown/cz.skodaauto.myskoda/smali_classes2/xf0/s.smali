.class public final synthetic Lxf0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Integer;

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Integer;

.field public final synthetic j:Z

.field public final synthetic k:Z

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;ILjava/lang/Integer;ZZLjava/lang/Integer;ZZII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/s;->d:Lx2/s;

    .line 5
    .line 6
    iput p2, p0, Lxf0/s;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/s;->f:Ljava/lang/Integer;

    .line 9
    .line 10
    iput-boolean p4, p0, Lxf0/s;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lxf0/s;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Lxf0/s;->i:Ljava/lang/Integer;

    .line 15
    .line 16
    iput-boolean p7, p0, Lxf0/s;->j:Z

    .line 17
    .line 18
    iput-boolean p8, p0, Lxf0/s;->k:Z

    .line 19
    .line 20
    iput p10, p0, Lxf0/s;->l:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

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
    move-result v9

    .line 14
    iget-object v0, p0, Lxf0/s;->d:Lx2/s;

    .line 15
    .line 16
    iget v1, p0, Lxf0/s;->e:I

    .line 17
    .line 18
    iget-object v2, p0, Lxf0/s;->f:Ljava/lang/Integer;

    .line 19
    .line 20
    iget-boolean v3, p0, Lxf0/s;->g:Z

    .line 21
    .line 22
    iget-boolean v4, p0, Lxf0/s;->h:Z

    .line 23
    .line 24
    iget-object v5, p0, Lxf0/s;->i:Ljava/lang/Integer;

    .line 25
    .line 26
    iget-boolean v6, p0, Lxf0/s;->j:Z

    .line 27
    .line 28
    iget-boolean v7, p0, Lxf0/s;->k:Z

    .line 29
    .line 30
    iget v10, p0, Lxf0/s;->l:I

    .line 31
    .line 32
    invoke-static/range {v0 .. v10}, Lxf0/t;->a(Lx2/s;ILjava/lang/Integer;ZZLjava/lang/Integer;ZZLl2/o;II)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0
.end method

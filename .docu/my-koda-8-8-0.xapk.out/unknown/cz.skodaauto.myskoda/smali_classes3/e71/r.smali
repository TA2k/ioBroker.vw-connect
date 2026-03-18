.class public final synthetic Le71/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lg4/p0;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:I

.field public final synthetic i:Z

.field public final synthetic j:I

.field public final synthetic k:J

.field public final synthetic l:Lr4/k;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le71/r;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Le71/r;->e:Lg4/p0;

    .line 7
    .line 8
    iput-object p3, p0, Le71/r;->f:Lx2/s;

    .line 9
    .line 10
    iput-object p4, p0, Le71/r;->g:Lay0/k;

    .line 11
    .line 12
    iput p5, p0, Le71/r;->h:I

    .line 13
    .line 14
    iput-boolean p6, p0, Le71/r;->i:Z

    .line 15
    .line 16
    iput p7, p0, Le71/r;->j:I

    .line 17
    .line 18
    iput-wide p8, p0, Le71/r;->k:J

    .line 19
    .line 20
    iput-object p10, p0, Le71/r;->l:Lr4/k;

    .line 21
    .line 22
    iput p11, p0, Le71/r;->m:I

    .line 23
    .line 24
    iput p12, p0, Le71/r;->n:I

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
    iget p1, p0, Le71/r;->m:I

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
    iget-object v0, p0, Le71/r;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Le71/r;->e:Lg4/p0;

    .line 20
    .line 21
    iget-object v2, p0, Le71/r;->f:Lx2/s;

    .line 22
    .line 23
    iget-object v3, p0, Le71/r;->g:Lay0/k;

    .line 24
    .line 25
    iget v4, p0, Le71/r;->h:I

    .line 26
    .line 27
    iget-boolean v5, p0, Le71/r;->i:Z

    .line 28
    .line 29
    iget v6, p0, Le71/r;->j:I

    .line 30
    .line 31
    iget-wide v7, p0, Le71/r;->k:J

    .line 32
    .line 33
    iget-object v9, p0, Le71/r;->l:Lr4/k;

    .line 34
    .line 35
    iget v12, p0, Le71/r;->n:I

    .line 36
    .line 37
    invoke-static/range {v0 .. v12}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method

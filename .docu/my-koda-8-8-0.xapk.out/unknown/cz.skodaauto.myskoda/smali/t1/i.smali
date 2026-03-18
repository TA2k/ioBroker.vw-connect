.class public final synthetic Lt1/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lg4/p0;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:I

.field public final synthetic i:Z

.field public final synthetic j:I

.field public final synthetic k:I

.field public final synthetic l:Le3/t;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lx2/s;Lg4/p0;Lay0/k;IZIILe3/t;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/i;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/i;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Lt1/i;->f:Lg4/p0;

    .line 9
    .line 10
    iput-object p4, p0, Lt1/i;->g:Lay0/k;

    .line 11
    .line 12
    iput p5, p0, Lt1/i;->h:I

    .line 13
    .line 14
    iput-boolean p6, p0, Lt1/i;->i:Z

    .line 15
    .line 16
    iput p7, p0, Lt1/i;->j:I

    .line 17
    .line 18
    iput p8, p0, Lt1/i;->k:I

    .line 19
    .line 20
    iput-object p9, p0, Lt1/i;->l:Le3/t;

    .line 21
    .line 22
    iput p10, p0, Lt1/i;->m:I

    .line 23
    .line 24
    iput p11, p0, Lt1/i;->n:I

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
    iget p1, p0, Lt1/i;->m:I

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
    iget-object v0, p0, Lt1/i;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Lt1/i;->e:Lx2/s;

    .line 20
    .line 21
    iget-object v2, p0, Lt1/i;->f:Lg4/p0;

    .line 22
    .line 23
    iget-object v3, p0, Lt1/i;->g:Lay0/k;

    .line 24
    .line 25
    iget v4, p0, Lt1/i;->h:I

    .line 26
    .line 27
    iget-boolean v5, p0, Lt1/i;->i:Z

    .line 28
    .line 29
    iget v6, p0, Lt1/i;->j:I

    .line 30
    .line 31
    iget v7, p0, Lt1/i;->k:I

    .line 32
    .line 33
    iget-object v8, p0, Lt1/i;->l:Le3/t;

    .line 34
    .line 35
    iget v11, p0, Lt1/i;->n:I

    .line 36
    .line 37
    invoke-static/range {v0 .. v11}, Lt1/l0;->c(Ljava/lang/String;Lx2/s;Lg4/p0;Lay0/k;IZIILe3/t;Ll2/o;II)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method

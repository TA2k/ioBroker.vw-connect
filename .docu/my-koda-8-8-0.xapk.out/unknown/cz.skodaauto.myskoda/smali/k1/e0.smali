.class public final synthetic Lk1/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Lk1/g;

.field public final synthetic f:Lk1/i;

.field public final synthetic g:Lx2/i;

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Lt2/b;

.field public final synthetic k:I

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lk1/g;Lk1/i;Lx2/i;IILt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk1/e0;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lk1/e0;->e:Lk1/g;

    .line 7
    .line 8
    iput-object p3, p0, Lk1/e0;->f:Lk1/i;

    .line 9
    .line 10
    iput-object p4, p0, Lk1/e0;->g:Lx2/i;

    .line 11
    .line 12
    iput p5, p0, Lk1/e0;->h:I

    .line 13
    .line 14
    iput p6, p0, Lk1/e0;->i:I

    .line 15
    .line 16
    iput-object p7, p0, Lk1/e0;->j:Lt2/b;

    .line 17
    .line 18
    iput p8, p0, Lk1/e0;->k:I

    .line 19
    .line 20
    iput p9, p0, Lk1/e0;->l:I

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
    iget p1, p0, Lk1/e0;->k:I

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
    iget-object v0, p0, Lk1/e0;->d:Lx2/s;

    .line 18
    .line 19
    iget-object v1, p0, Lk1/e0;->e:Lk1/g;

    .line 20
    .line 21
    iget-object v2, p0, Lk1/e0;->f:Lk1/i;

    .line 22
    .line 23
    iget-object v3, p0, Lk1/e0;->g:Lx2/i;

    .line 24
    .line 25
    iget v4, p0, Lk1/e0;->h:I

    .line 26
    .line 27
    iget v5, p0, Lk1/e0;->i:I

    .line 28
    .line 29
    iget-object v6, p0, Lk1/e0;->j:Lt2/b;

    .line 30
    .line 31
    iget v9, p0, Lk1/e0;->l:I

    .line 32
    .line 33
    invoke-static/range {v0 .. v9}, Lk1/d;->b(Lx2/s;Lk1/g;Lk1/i;Lx2/i;IILt2/b;Ll2/o;II)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method

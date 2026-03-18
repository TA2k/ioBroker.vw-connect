.class public final synthetic Luz/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:I

.field public final synthetic i:J

.field public final synthetic j:Lg4/p0;

.field public final synthetic k:J

.field public final synthetic l:I

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JIII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luz/b;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Luz/b;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Luz/b;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Luz/b;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput p5, p0, Luz/b;->h:I

    .line 13
    .line 14
    iput-wide p6, p0, Luz/b;->i:J

    .line 15
    .line 16
    iput-object p8, p0, Luz/b;->j:Lg4/p0;

    .line 17
    .line 18
    iput-wide p9, p0, Luz/b;->k:J

    .line 19
    .line 20
    iput p11, p0, Luz/b;->l:I

    .line 21
    .line 22
    iput p12, p0, Luz/b;->m:I

    .line 23
    .line 24
    iput p13, p0, Luz/b;->n:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object v11, p1

    .line 2
    check-cast v11, Ll2/o;

    .line 3
    .line 4
    move-object/from16 v0, p2

    .line 5
    .line 6
    check-cast v0, Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget v0, p0, Luz/b;->m:I

    .line 12
    .line 13
    or-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v12

    .line 19
    iget-object v0, p0, Luz/b;->d:Lx2/s;

    .line 20
    .line 21
    iget-object v1, p0, Luz/b;->e:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v2, p0, Luz/b;->f:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v3, p0, Luz/b;->g:Ljava/lang/String;

    .line 26
    .line 27
    iget v4, p0, Luz/b;->h:I

    .line 28
    .line 29
    iget-wide v5, p0, Luz/b;->i:J

    .line 30
    .line 31
    iget-object v7, p0, Luz/b;->j:Lg4/p0;

    .line 32
    .line 33
    iget-wide v8, p0, Luz/b;->k:J

    .line 34
    .line 35
    iget v10, p0, Luz/b;->l:I

    .line 36
    .line 37
    iget v13, p0, Luz/b;->n:I

    .line 38
    .line 39
    invoke-static/range {v0 .. v13}, Luz/g;->k(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJLg4/p0;JILl2/o;II)V

    .line 40
    .line 41
    .line 42
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0
.end method

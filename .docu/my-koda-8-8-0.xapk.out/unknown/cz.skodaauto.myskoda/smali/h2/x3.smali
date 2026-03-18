.class public final synthetic Lh2/x3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/Long;

.field public final synthetic e:Ljava/lang/Long;

.field public final synthetic f:J

.field public final synthetic g:I

.field public final synthetic h:Lay0/n;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Li2/z;

.field public final synthetic k:Lgy0/j;

.field public final synthetic l:Lh2/g2;

.field public final synthetic m:Lh2/e8;

.field public final synthetic n:Lh2/z1;

.field public final synthetic o:Lc3/q;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Long;Ljava/lang/Long;JILay0/n;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Lc3/q;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/x3;->d:Ljava/lang/Long;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/x3;->e:Ljava/lang/Long;

    .line 7
    .line 8
    iput-wide p3, p0, Lh2/x3;->f:J

    .line 9
    .line 10
    iput p5, p0, Lh2/x3;->g:I

    .line 11
    .line 12
    iput-object p6, p0, Lh2/x3;->h:Lay0/n;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/x3;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/x3;->j:Li2/z;

    .line 17
    .line 18
    iput-object p9, p0, Lh2/x3;->k:Lgy0/j;

    .line 19
    .line 20
    iput-object p10, p0, Lh2/x3;->l:Lh2/g2;

    .line 21
    .line 22
    iput-object p11, p0, Lh2/x3;->m:Lh2/e8;

    .line 23
    .line 24
    iput-object p12, p0, Lh2/x3;->n:Lh2/z1;

    .line 25
    .line 26
    iput-object p13, p0, Lh2/x3;->o:Lc3/q;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v13, p1

    .line 4
    .line 5
    check-cast v13, Ll2/o;

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
    const/4 v1, 0x1

    .line 15
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v14

    .line 19
    iget-object v1, v0, Lh2/x3;->d:Ljava/lang/Long;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    iget-object v1, v0, Lh2/x3;->e:Ljava/lang/Long;

    .line 23
    .line 24
    move-object v4, v2

    .line 25
    iget-wide v2, v0, Lh2/x3;->f:J

    .line 26
    .line 27
    move-object v5, v4

    .line 28
    iget v4, v0, Lh2/x3;->g:I

    .line 29
    .line 30
    move-object v6, v5

    .line 31
    iget-object v5, v0, Lh2/x3;->h:Lay0/n;

    .line 32
    .line 33
    move-object v7, v6

    .line 34
    iget-object v6, v0, Lh2/x3;->i:Lay0/k;

    .line 35
    .line 36
    move-object v8, v7

    .line 37
    iget-object v7, v0, Lh2/x3;->j:Li2/z;

    .line 38
    .line 39
    move-object v9, v8

    .line 40
    iget-object v8, v0, Lh2/x3;->k:Lgy0/j;

    .line 41
    .line 42
    move-object v10, v9

    .line 43
    iget-object v9, v0, Lh2/x3;->l:Lh2/g2;

    .line 44
    .line 45
    move-object v11, v10

    .line 46
    iget-object v10, v0, Lh2/x3;->m:Lh2/e8;

    .line 47
    .line 48
    move-object v12, v11

    .line 49
    iget-object v11, v0, Lh2/x3;->n:Lh2/z1;

    .line 50
    .line 51
    iget-object v0, v0, Lh2/x3;->o:Lc3/q;

    .line 52
    .line 53
    move-object v15, v12

    .line 54
    move-object v12, v0

    .line 55
    move-object v0, v15

    .line 56
    invoke-static/range {v0 .. v14}, Lh2/f4;->c(Ljava/lang/Long;Ljava/lang/Long;JILay0/n;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Lc3/q;Ll2/o;I)V

    .line 57
    .line 58
    .line 59
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object v0
.end method

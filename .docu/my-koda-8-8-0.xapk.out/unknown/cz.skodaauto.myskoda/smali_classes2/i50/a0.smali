.class public final synthetic Li50/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh50/w0;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Lay0/a;

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(Lh50/w0;Ljava/lang/String;ZZZLay0/a;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li50/a0;->d:Lh50/w0;

    .line 5
    .line 6
    iput-object p2, p0, Li50/a0;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-boolean p3, p0, Li50/a0;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Li50/a0;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Li50/a0;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Li50/a0;->i:Lay0/a;

    .line 15
    .line 16
    iput p7, p0, Li50/a0;->j:I

    .line 17
    .line 18
    iput p8, p0, Li50/a0;->k:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    move-object v6, p1

    .line 2
    check-cast v6, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li50/a0;->j:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v7

    .line 17
    iget-object v0, p0, Li50/a0;->d:Lh50/w0;

    .line 18
    .line 19
    iget-object v1, p0, Li50/a0;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v2, p0, Li50/a0;->f:Z

    .line 22
    .line 23
    iget-boolean v3, p0, Li50/a0;->g:Z

    .line 24
    .line 25
    iget-boolean v4, p0, Li50/a0;->h:Z

    .line 26
    .line 27
    iget-object v5, p0, Li50/a0;->i:Lay0/a;

    .line 28
    .line 29
    iget v8, p0, Li50/a0;->k:I

    .line 30
    .line 31
    invoke-static/range {v0 .. v8}, Li50/c;->p(Lh50/w0;Ljava/lang/String;ZZZLay0/a;Ll2/o;II)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method

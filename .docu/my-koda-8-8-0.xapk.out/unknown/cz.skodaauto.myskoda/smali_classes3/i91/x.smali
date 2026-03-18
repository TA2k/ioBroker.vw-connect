.class public final synthetic Li91/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:Li91/h1;

.field public final synthetic j:J

.field public final synthetic k:I

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lay0/a;Lx2/s;ZLjava/lang/Integer;Li91/h1;JII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/x;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Li91/x;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Li91/x;->f:Lx2/s;

    .line 9
    .line 10
    iput-boolean p4, p0, Li91/x;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Li91/x;->h:Ljava/lang/Integer;

    .line 13
    .line 14
    iput-object p6, p0, Li91/x;->i:Li91/h1;

    .line 15
    .line 16
    iput-wide p7, p0, Li91/x;->j:J

    .line 17
    .line 18
    iput p9, p0, Li91/x;->k:I

    .line 19
    .line 20
    iput p10, p0, Li91/x;->l:I

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
    iget p1, p0, Li91/x;->k:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v9

    .line 17
    iget-object v0, p0, Li91/x;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Li91/x;->e:Lay0/a;

    .line 20
    .line 21
    iget-object v2, p0, Li91/x;->f:Lx2/s;

    .line 22
    .line 23
    iget-boolean v3, p0, Li91/x;->g:Z

    .line 24
    .line 25
    iget-object v4, p0, Li91/x;->h:Ljava/lang/Integer;

    .line 26
    .line 27
    iget-object v5, p0, Li91/x;->i:Li91/h1;

    .line 28
    .line 29
    iget-wide v6, p0, Li91/x;->j:J

    .line 30
    .line 31
    iget v10, p0, Li91/x;->l:I

    .line 32
    .line 33
    invoke-static/range {v0 .. v10}, Li91/j0;->x0(Ljava/lang/String;Lay0/a;Lx2/s;ZLjava/lang/Integer;Li91/h1;JLl2/o;II)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method

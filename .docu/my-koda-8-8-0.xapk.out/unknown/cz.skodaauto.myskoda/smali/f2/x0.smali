.class public abstract Lf2/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lg4/p0;

.field public static final b:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 15

    .line 1
    new-instance v13, Lr4/i;

    .line 2
    .line 3
    sget v0, Lr4/f;->b:F

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v13, v1, v0}, Lr4/i;-><init>(IF)V

    .line 7
    .line 8
    .line 9
    sget-object v0, Lg4/p0;->d:Lg4/p0;

    .line 10
    .line 11
    sget-object v12, Lf2/r;->a:Lg4/y;

    .line 12
    .line 13
    const v14, 0xe7ffff

    .line 14
    .line 15
    .line 16
    const-wide/16 v1, 0x0

    .line 17
    .line 18
    const-wide/16 v3, 0x0

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    const/4 v6, 0x0

    .line 22
    const-wide/16 v7, 0x0

    .line 23
    .line 24
    const/4 v9, 0x0

    .line 25
    const-wide/16 v10, 0x0

    .line 26
    .line 27
    invoke-static/range {v0 .. v14}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lf2/x0;->a:Lg4/p0;

    .line 32
    .line 33
    new-instance v0, Lf2/h0;

    .line 34
    .line 35
    const/4 v1, 0x3

    .line 36
    invoke-direct {v0, v1}, Lf2/h0;-><init>(I)V

    .line 37
    .line 38
    .line 39
    new-instance v1, Ll2/u2;

    .line 40
    .line 41
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 42
    .line 43
    .line 44
    sput-object v1, Lf2/x0;->b:Ll2/u2;

    .line 45
    .line 46
    return-void
.end method

.method public static final a(Lg4/p0;)Lg4/p0;
    .locals 15

    .line 1
    iget-object v1, p0, Lg4/p0;->a:Lg4/g0;

    .line 2
    .line 3
    iget-object v1, v1, Lg4/g0;->f:Lk4/n;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 v13, 0x0

    .line 9
    const v14, 0xffffdf

    .line 10
    .line 11
    .line 12
    const-wide/16 v1, 0x0

    .line 13
    .line 14
    const-wide/16 v3, 0x0

    .line 15
    .line 16
    const/4 v5, 0x0

    .line 17
    sget-object v6, Lk4/n;->d:Lk4/j;

    .line 18
    .line 19
    const-wide/16 v7, 0x0

    .line 20
    .line 21
    const/4 v9, 0x0

    .line 22
    const-wide/16 v10, 0x0

    .line 23
    .line 24
    const/4 v12, 0x0

    .line 25
    move-object v0, p0

    .line 26
    invoke-static/range {v0 .. v14}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    return-object v0
.end method

.class public final Luj0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwj0/a;


# static fields
.field public static final e:Lxj0/b;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lxj0/b;

    .line 2
    .line 3
    new-instance v1, Lxj0/f;

    .line 4
    .line 5
    const-wide/high16 v2, 0x404a000000000000L    # 52.0

    .line 6
    .line 7
    const-wide/high16 v4, 0x4028000000000000L    # 12.0

    .line 8
    .line 9
    invoke-direct {v1, v2, v3, v4, v5}, Lxj0/f;-><init>(DD)V

    .line 10
    .line 11
    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x0

    .line 14
    const/high16 v2, 0x40600000    # 3.5f

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    const/4 v5, 0x0

    .line 19
    invoke-direct/range {v0 .. v7}, Lxj0/b;-><init>(Lxj0/f;FZILxj0/f;Lxj0/f;Z)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Luj0/c;->e:Lxj0/b;

    .line 23
    .line 24
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lxj0/w;->a:Lxj0/w;

    .line 5
    .line 6
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Luj0/c;->a:Lyy0/c2;

    .line 11
    .line 12
    new-instance v1, Lyy0/l1;

    .line 13
    .line 14
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 15
    .line 16
    .line 17
    iput-object v1, p0, Luj0/c;->b:Lyy0/l1;

    .line 18
    .line 19
    sget-object v0, Luj0/c;->e:Lxj0/b;

    .line 20
    .line 21
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Luj0/c;->c:Lyy0/c2;

    .line 26
    .line 27
    new-instance v1, Lyy0/l1;

    .line 28
    .line 29
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 30
    .line 31
    .line 32
    iput-object v1, p0, Luj0/c;->d:Lyy0/l1;

    .line 33
    .line 34
    return-void
.end method

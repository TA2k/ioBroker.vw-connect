.class public interface abstract Lx51/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final o1:Lx51/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lx51/b;->e:Lx51/b;

    .line 2
    .line 3
    sput-object v0, Lx51/c;->o1:Lx51/b;

    .line 4
    .line 5
    return-void
.end method

.method public static synthetic f(Lx51/c;Ljava/lang/String;Ljava/lang/Exception;Lay0/a;I)V
    .locals 2

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object p1, v1

    .line 7
    :cond_0
    and-int/lit8 p4, p4, 0x2

    .line 8
    .line 9
    if-eqz p4, :cond_1

    .line 10
    .line 11
    move-object p2, v1

    .line 12
    :cond_1
    invoke-interface {p0, p1, p2, p3}, Lx51/c;->d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static synthetic i(Lx51/c;Ljava/lang/String;Lay0/a;I)V
    .locals 1

    .line 1
    and-int/lit8 p3, p3, 0x1

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p3, :cond_0

    .line 5
    .line 6
    move-object p1, v0

    .line 7
    :cond_0
    invoke-interface {p0, p1, v0, p2}, Lx51/c;->j(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public abstract d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
.end method

.method public abstract j(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
.end method

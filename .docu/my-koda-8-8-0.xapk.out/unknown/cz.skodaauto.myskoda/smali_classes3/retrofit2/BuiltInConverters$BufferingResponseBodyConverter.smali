.class final Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Converter;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/BuiltInConverters;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "BufferingResponseBodyConverter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lretrofit2/Converter<",
        "Ld01/v0;",
        "Ld01/v0;",
        ">;"
    }
.end annotation


# static fields
.field public static final d:Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;

    .line 2
    .line 3
    invoke-direct {v0}, Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;->d:Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Ld01/v0;

    .line 2
    .line 3
    :try_start_0
    new-instance p0, Lu01/f;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Ld01/v0;->p0()Lu01/h;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-interface {v0, p0}, Lu01/h;->L(Lu01/g;)J

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1}, Ld01/v0;->d()Ld01/d0;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {p1}, Ld01/v0;->b()J

    .line 20
    .line 21
    .line 22
    move-result-wide v1

    .line 23
    sget-object v3, Ld01/v0;->d:Ld01/u0;

    .line 24
    .line 25
    new-instance v3, Ld01/u0;

    .line 26
    .line 27
    invoke-direct {v3, v0, v1, v2, p0}, Ld01/u0;-><init>(Ld01/d0;JLu01/f;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    .line 29
    .line 30
    invoke-virtual {p1}, Ld01/v0;->close()V

    .line 31
    .line 32
    .line 33
    return-object v3

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    invoke-virtual {p1}, Ld01/v0;->close()V

    .line 36
    .line 37
    .line 38
    throw p0
.end method
